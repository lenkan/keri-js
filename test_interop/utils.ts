import assert from "node:assert";
import type { Buffer } from "node:buffer";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { Controller } from "@keri-js/infra/controller";
import { createMailboxRouter, Mailbox } from "@keri-js/infra/mailbox";
import { createListener, type Logger, NodeSqliteDatabase, SqliteControllerStorage } from "@keri-js/infra/node";
import { createRouter, Witness } from "@keri-js/infra/witness";
import { KERIPy } from "./keripy.ts";

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

// Remembering every port ever handed out eventually covers enough of the ephemeral range that the
// kernel, which hands them out in order, can only offer ports already in the set. A window of recent
// ones is what the guarantee actually needs: a port handed out this long ago is either bound or gone.
const RECENT_PORTS = 256;
const handedOut = new Set<number>();

function rememberPort(port: number): void {
  handedOut.add(port);
  if (handedOut.size > RECENT_PORTS) {
    handedOut.delete(handedOut.values().next().value as number);
  }
}

function bindEphemeral(): Promise<{ server: Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, () => resolve({ server, port: (server.address() as AddressInfo).port }));
    server.on("error", reject);
  });
}

// Only for `startKeripyWitness`: `kli` binds its own sockets in another process, so the ports have to
// be released before it can take them. Everything served in-process uses `listen` below instead,
// which never releases the port and so cannot lose it to whatever binds next.
//
// The ports are held open all at once and only released together, so no two of them can be equal,
// and `handedOut` keeps that guarantee across calls: a bind landing on a port already given away
// stays open while it re-rolls, so the OS cannot offer it again. What survives is a race with a
// process outside this one, which `startKeripyWitness` retries.
const REROLLS = 10;

async function allocatePorts(count: number): Promise<number[]> {
  const held: Server[] = [];
  const ports: number[] = [];

  try {
    while (ports.length < count) {
      let port = 0;
      for (let attempt = 0; attempt < REROLLS; attempt++) {
        const bound = await bindEphemeral();
        held.push(bound.server);
        port = bound.port;
        if (!handedOut.has(port)) {
          break;
        }
      }
      // A range too crowded to re-roll out of takes the repeat rather than failing: the ports of
      // this call are still distinct from each other, and the spawn retry covers the rest.
      rememberPort(port);
      ports.push(port);
    }
  } finally {
    await Promise.all(held.map((server) => new Promise((resolve) => server.close(resolve))));
  }

  return ports;
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

  const witness = new Witness({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
    url,
  });

  serve(createRouter(witness, { logger: serverLogger }));

  return { aid: witness.aid, url, oobi: `${url}/oobi` };
}

export async function startKerijsMailbox(opts: { port?: number; signal?: AbortSignal } = {}): Promise<Endpoint> {
  const { url, serve } = await listen(opts.signal, opts.port);

  const mailbox = new Mailbox({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
    url,
  });

  serve(createMailboxRouter(mailbox, { logger: serverLogger }));

  return { aid: mailbox.aid, url, oobi: `${url}/oobi` };
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
