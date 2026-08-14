import type { ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { Controller } from "keri";
import { createMailboxRouter, Mailbox } from "keri/mailbox";
import { createListener, type Logger } from "keri/nodejs-utils";
import { NodeSqliteDatabase, SqliteControllerStorage } from "keri/sqlite-storage";
import { createRouter, Witness } from "keri/witness";
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

// Only for `startKeripyWitness`: `kli` binds its own sockets in another process, so the port has to
// be released before it can take it. Everything served in-process uses `listen` below instead, which
// never releases the port and so cannot lose it to whatever binds next.
function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, () => {
      const { port } = server.address() as AddressInfo;
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
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

const witnesses = new Set<ChildProcess>();

// A witness that outlives the `after()` hook's SIGTERM holds its stdio pipes open, which keeps the
// test process alive past the last test. SIGKILL is the only signal left once we are already exiting.
process.on("exit", () => {
  for (const child of witnesses) {
    child.kill("SIGKILL");
  }
});

export async function startKeripyWitness(
  opts: { port?: number; salt?: string; signal?: AbortSignal; logLevel?: string } = {},
): Promise<KeripyWitness> {
  const httpPort = opts.port ?? (await findFreePort());
  const tcpPort = await findFreePort();
  const url = `http://localhost:${httpPort}`;

  const keripy = new KERIPy({});
  await keripy.init({ salt: opts.salt });
  await keripy.incept({ toad: 0, transferable: false });
  const aid = await keripy.aid();
  await keripy.ends.add({ eid: aid, role: "controller" });
  await keripy.location.add({ url });
  const child = keripy.witness.start({ http: httpPort, tcp: tcpPort, logLevel: opts.logLevel ?? "ERROR" });

  witnesses.add(child);
  child.once("exit", () => witnesses.delete(child));

  opts.signal?.addEventListener("abort", () => {
    child.kill();
  });

  const oobiUrl = `${url}/oobi`;
  const deadline = Date.now() + 30000;
  let ready = false;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(oobiUrl);
      if (response.ok || response.status === 404) {
        ready = true;
        break;
      }
    } catch {
      // not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  if (!ready) {
    child.kill();
    throw new Error(`KERIpy witness at ${oobiUrl} did not become reachable within 30s`);
  }

  return { aid, url, oobi: oobiUrl, kli: keripy };
}

export async function collectAsync<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const item of iterable) {
    result.push(item);
  }
  return result;
}
