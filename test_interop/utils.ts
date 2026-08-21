import assert from "node:assert";
import type { Buffer } from "node:buffer";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { Controller } from "@keri-js/infra/controller";
import { createMailboxRouter, Mailbox } from "@keri-js/infra/mailbox";
import { createListener, type Logger, NodeSqliteDatabase } from "@keri-js/infra/node";
import { createPortalRouter } from "@keri-js/infra/portal";
import { SqliteControllerStorage } from "@keri-js/infra/sqlite";
import {
  createVerifierRouter,
  type KeyEventStore,
  type SessionStore,
  type StoredKeyEvent,
  Verifier,
} from "@keri-js/infra/verifier";
import { createRouter, Witness } from "@keri-js/infra/witness";
import { KERIPy } from "../test_utils/keripy.ts";
import { allocatePorts } from "../test_utils/ports.ts";

export interface Endpoint {
  aid: string;
  url: string;
  oobi: string;
}

export interface KeripyWitness extends Endpoint {
  kli: KERIPy;
}

export function createController() {
  const controller = new Controller({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
  });

  return controller;
}

const serverLogger: Logger = {
  debug: (msg, meta) => console.log(`[server] ${msg}`, meta ?? ""),
  info: (msg, meta) => console.log(`[server] ${msg}`, meta ?? ""),
  warn: (msg, meta) => console.warn(`[server] ${msg}`, meta ?? ""),
  error: (msg, meta) => console.error(`[server] ${msg}`, meta ?? ""),
};

type Router = (request: Request) => Promise<Response>;

// Binds first and reads the port off the live server, so the caller can build a router that knows
// its own URL without the port ever being unbound.
async function listen(signal?: AbortSignal, port = 0): Promise<{ url: string; serve: (router: Router) => void }> {
  const server = createServer();

  const bound = await new Promise<number>((resolve, reject) => {
    const onError = (err: Error) => {
      server.off("listening", onListening);
      reject(err);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve((server.address() as AddressInfo).port);
    };

    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port);
  });

  signal?.addEventListener("abort", () => {
    server.close();
  });

  return {
    url: `http://localhost:${bound}`,
    serve: (router) => server.on("request", createListener(router, { logger: serverLogger })),
  };
}

export async function startKerijsWitness(opts: { port?: number; signal?: AbortSignal } = {}): Promise<Endpoint> {
  const { url, serve } = await listen(opts.signal, opts.port);

  const witness = await Witness.create({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
    url,
  });

  serve(createRouter(witness, { logger: serverLogger }));

  return { aid: witness.aid, url, oobi: `${url}/oobi` };
}

/**
 * The full portal composition — mailbox + receipting witness + intake
 * dispatch under one identity — as the deployed worker runs it, served from
 * Node for the interop harness.
 */
export async function startKerijsPortal(opts: { port?: number; signal?: AbortSignal } = {}): Promise<Endpoint> {
  const { url, serve } = await listen(opts.signal, opts.port);

  const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));
  // One key for both faces, so mailbox and witness ARE the same portal identity.
  const privateKey = crypto.getRandomValues(new Uint8Array(32));

  // See startKerijsMailbox for why the advertised location carries "/.".
  const [mailbox, witness] = await Promise.all([
    Mailbox.create({ storage, privateKey, url: `${url}/.` }),
    Witness.create({ storage, privateKey, url: `${url}/.` }),
  ]);

  serve(createPortalRouter(mailbox, witness, storage, { logger: serverLogger }));

  return { aid: mailbox.aid, url, oobi: `${url}/oobi` };
}

export async function startKerijsMailbox(opts: { port?: number; signal?: AbortSignal } = {}): Promise<Endpoint> {
  const { url, serve } = await listen(opts.signal, opts.port);

  const mailbox = await Mailbox.create({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
    // The "/." path is for KERIpy 1.3.3's `kli mailbox add`, which composes its
    // enrollment path as `{loc path}/mailboxes` while hio defaults an empty loc
    // path to "/" — a bare origin therefore yields "//mailboxes", which hio
    // rejects as a hostname change. "/." keeps every composed path valid
    // ("/./mailboxes", "/./") and servers normalize the dot segment away.
    url: `${url}/.`,
  });

  serve(createMailboxRouter(mailbox, { logger: serverLogger }));

  return { aid: mailbox.aid, url, oobi: `${url}/oobi` };
}

export async function startKerijsVerifier(opts: { port?: number; signal?: AbortSignal } = {}): Promise<Endpoint> {
  const { url, serve } = await listen(opts.signal, opts.port);

  // Deno KV backs this in the deployed app; the router only needs the interface.
  const entries = new Map<string, string>();
  const sessions: SessionStore = {
    get: async (token) => entries.get(token) ?? null,
    put: async (token, cesr) => {
      entries.set(token, cesr);
    },
  };

  const events = new Map<string, StoredKeyEvent>();
  const keyEvents: KeyEventStore = {
    getEvent: async (aid, sn) => events.get(`${aid}:${sn}`) ?? null,
    putEvent: async (aid, sn, event) => {
      events.set(`${aid}:${sn}`, event);
    },
  };

  const verifier = await Verifier.create({ url });
  serve(createVerifierRouter(verifier, sessions, keyEvents, { logger: serverLogger }));

  return { aid: verifier.aid, url, oobi: verifier.oobi };
}

const witnesses = new Set<ChildProcessWithoutNullStreams>();

// A witness that outlives the `after()` hook's SIGTERM holds its stdio pipes open, which keeps the
// test process alive past the last test. SIGKILL is the only signal left once we are already exiting.
process.on("exit", () => {
  for (const child of witnesses) {
    child.kill("SIGKILL");
  }
});

const READY_TIMEOUT = 30000;

// Thrown when `kli` is gone: the ports it was given are the likely reason, so this is the one
// failure `startKeripyWitness` retries.
class WitnessExitedError extends Error {}

// `kli` writes "cannot create http server on port N" to stdout and the traceback to stderr, so both
// streams go into the tail.
function watchOutput(child: ChildProcessWithoutNullStreams): { exited: Promise<number | null>; tail: () => string } {
  let tail = "";
  const append = (chunk: Buffer) => {
    tail = (tail + chunk.toString()).slice(-2000);
  };

  child.stdout.on("data", append);
  child.stderr.on("data", append);

  return {
    // `close` rather than `exit`, so the tail has everything the process wrote before it died.
    exited: new Promise((resolve) => child.once("close", resolve)),
    tail: () => tail.trim().replaceAll("\n", " "),
  };
}

async function waitUntilReachable(
  child: ChildProcessWithoutNullStreams,
  ports: { http: number; tcp: number },
): Promise<void> {
  const { exited, tail } = watchOutput(child);
  let stopped = false;

  const poll = (async () => {
    const deadline = Date.now() + READY_TIMEOUT;
    while (Date.now() < deadline && !stopped) {
      try {
        const response = await fetch(`http://localhost:${ports.http}/oobi`);
        if (response.ok || response.status === 404) {
          return "reachable" as const;
        }
      } catch {
        // not ready yet
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    return "timeout" as const;
  })();

  const outcome = await Promise.race([poll, exited.then(() => "exited" as const)]);
  stopped = true;

  const where = `KERIpy witness on :${ports.http}/:${ports.tcp}`;
  if (outcome === "exited") {
    throw new WitnessExitedError(
      `${where} exited (code=${await exited}) before becoming reachable: ${tail() || "no output"}`,
    );
  }
  if (outcome === "timeout") {
    throw new Error(`${where} did not answer within ${READY_TIMEOUT / 1000}s (process still running)`);
  }
}

export async function startKeripyWitness(
  opts: { port?: number; salt?: string; signal?: AbortSignal; logLevel?: string } = {},
): Promise<KeripyWitness> {
  const keripy = new KERIPy({});
  await keripy.init({ salt: opts.salt });
  await keripy.incept({ toad: 0, transferable: false });
  const aid = await keripy.aid();
  await keripy.ends.add({ eid: aid, role: "controller" });

  let child: ChildProcessWithoutNullStreams | undefined;
  opts.signal?.addEventListener("abort", () => {
    child?.kill();
  });

  // A port the caller picked is theirs to get right, so only auto-allocated ports are worth another
  // roll. Everything above is port-independent and stays out of the loop.
  const attempts = opts.port === undefined ? 3 : 1;
  for (let attempt = 1; ; attempt++) {
    const [allocated, allocatedTcp] = await allocatePorts(opts.port === undefined ? 2 : 1);
    const httpPort = opts.port ?? allocated;
    const tcpPort = opts.port === undefined ? allocatedTcp : allocated;
    assert(httpPort !== tcpPort, `KERIpy witness given the same port twice: ${httpPort}`);

    const url = `http://localhost:${httpPort}`;
    // The URL carries the http port, so every attempt re-publishes it; the newest reply wins.
    await keripy.location.add({ url });
    child = keripy.witness.start({ http: httpPort, tcp: tcpPort, logLevel: opts.logLevel ?? "ERROR" });

    const spawned = child;
    witnesses.add(spawned);
    spawned.once("exit", () => witnesses.delete(spawned));

    try {
      await waitUntilReachable(child, { http: httpPort, tcp: tcpPort });
      return { aid, url, oobi: `${url}/oobi`, kli: keripy };
    } catch (error) {
      child.kill();
      if (attempt >= attempts || !(error instanceof WitnessExitedError)) {
        throw error;
      }
      console.warn(`[keripy] attempt ${attempt}/${attempts} failed, retrying on fresh ports: ${error.message}`);
    }
  }
}

export async function collectAsync<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const item of iterable) {
    result.push(item);
  }
  return result;
}
