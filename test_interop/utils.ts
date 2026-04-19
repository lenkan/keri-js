import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { Controller } from "#keri";
import { createMailboxRouter, Mailbox } from "#keri/mailbox";
import { createListener } from "#keri/nodejs-utils";
import { NodeSqliteDatabase, SqliteControllerStorage } from "#keri/storage/sqlite";
import { createRouter, Witness as WitnessNode } from "#keri/witness";
import { KERIPy } from "./keripy.ts";

export interface Witness {
  aid: string;
  url: string;
  oobi: string;
}

export interface KeripyWitness extends Witness {
  kli: KERIPy;
}

export function createController() {
  const controller = new Controller({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
  });

  return controller;
}

function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, () => {
      const address = server.address();
      if (address && typeof address === "object") {
        const port = address.port;
        server.close(() => resolve(port));
      } else {
        server.close(() => reject(new Error("Failed to find free port")));
      }
    });
    server.on("error", (err) => {
      reject(err);
    });
  });
}

async function serve(router: (request: Request) => Promise<Response>, port: number, signal?: AbortSignal) {
  const listener = createListener(router, (message, context) => {
    const prefix = `[server]`;
    console.log(`${prefix} ${message}`, context);
  });
  const server = createServer(listener);

  await new Promise<void>((resolve, reject) => {
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    const onError = (err: Error) => {
      server.off("listening", onListening);
      reject(err);
    };

    server.once("listening", onListening);
    server.once("error", onError);
    server.listen(port);
  });

  signal?.addEventListener("abort", () => {
    server.close();
  });
}

export async function startKerijsWitness(opts: { port?: number; signal?: AbortSignal } = {}): Promise<Witness> {
  const port = opts.port ?? (await findFreePort());
  const url = `http://localhost:${port}`;

  const witness = new WitnessNode({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
    url: `http://localhost:${port}`,
  });

  const router = createRouter(witness);

  await serve(router, port, opts.signal);

  return { aid: witness.aid, url, oobi: `${url}/oobi` };
}

export async function startKerijsMailbox(opts: { port?: number; signal?: AbortSignal } = {}): Promise<Witness> {
  const port = opts.port ?? (await findFreePort());
  const url = `http://localhost:${port}`;

  const mailbox = new Mailbox({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
    url: `http://localhost:${port}`,
  });

  const router = createMailboxRouter(mailbox);

  await serve(router, port, opts.signal);

  return { aid: mailbox.aid, url, oobi: `${url}/oobi` };
}

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
