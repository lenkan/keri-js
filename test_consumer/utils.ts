import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
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

// The witness and mailbox sign their own location into the OOBI they serve, so the URL has to be
// known before they are constructed. Bind first and read the port off the live server rather than
// probing for a free one — releasing a probed port leaves a window for another listener to take it.
type Router = (request: Request) => Promise<Response>;

async function listen(signal: AbortSignal): Promise<{ url: string; serve: (router: Router) => void }> {
  const server = createServer();

  const port = await new Promise<number>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve((server.address() as AddressInfo).port);
    };

    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(0);
  });

  signal.addEventListener("abort", () => server.close());

  return {
    url: `http://localhost:${port}`,
    serve: (router) => server.on("request", createListener(router)),
  };
}

export async function startWitness(signal: AbortSignal): Promise<Endpoint> {
  const { url, serve } = await listen(signal);
  const witness = new Witness({ storage: storage(), url });
  serve(createRouter(witness));

  return { aid: witness.aid, url, oobi: `${url}/oobi` };
}

export async function startMailbox(signal: AbortSignal): Promise<Endpoint> {
  const { url, serve } = await listen(signal);
  const mailbox = new Mailbox({ storage: storage(), url });
  serve(createMailboxRouter(mailbox));

  return { aid: mailbox.aid, url, oobi: `${url}/oobi` };
}

export async function collectAsync<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const item of iterable) {
    result.push(item);
  }
  return result;
}
