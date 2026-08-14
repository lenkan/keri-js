import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { Controller } from "keri";
import { createMailboxRouter, Mailbox } from "keri/mailbox";
import { createListener } from "keri/nodejs-utils";
import { NodeSqliteDatabase, SqliteControllerStorage } from "keri/sqlite-storage";
import { createRouter, Witness } from "keri/witness";

export interface Endpoint {
  aid: string;
  url: string;
  oobi: string;
}

function storage() {
  return new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));
}

export function createController(): Controller {
  return new Controller({ storage: storage() });
}

// The witness and mailbox sign their own location into the OOBI they serve, so the port has to be
// known before the server is constructed.
function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, () => {
      const address = server.address();
      if (address && typeof address === "object") {
        const { port } = address;
        server.close(() => resolve(port));
      } else {
        server.close(() => reject(new Error("Failed to find a free port")));
      }
    });
  });
}

async function serve(router: (request: Request) => Promise<Response>, port: number, signal: AbortSignal) {
  const server = createServer(createListener(router));

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => resolve());
  });

  signal.addEventListener("abort", () => server.close());
}

export async function startWitness(signal: AbortSignal): Promise<Endpoint> {
  const port = await findFreePort();
  const url = `http://localhost:${port}`;

  const witness = new Witness({ storage: storage(), url });
  await serve(createRouter(witness), port, signal);

  return { aid: witness.aid, url, oobi: `${url}/oobi` };
}

export async function startMailbox(signal: AbortSignal): Promise<Endpoint> {
  const port = await findFreePort();
  const url = `http://localhost:${port}`;

  const mailbox = new Mailbox({ storage: storage(), url });
  await serve(createMailboxRouter(mailbox), port, signal);

  return { aid: mailbox.aid, url, oobi: `${url}/oobi` };
}

export async function collectAsync<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const item of iterable) {
    result.push(item);
  }
  return result;
}
