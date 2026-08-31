import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import debug from "debug";
import { generateKeyPair } from "../src/main.ts";
import { type Logger, MemoryStore, Witness } from "../src/witness/main.ts";
import { createListener } from "../test_utils/serve.ts";

export interface WitnessEndpoint {
  aid: string;
  url: string;
  /** The OOBI KERIpy resolves to learn this witness. */
  oobi: string;
}

const log = debug("witness");
const logger: Logger | undefined = log.enabled
  ? {
      debug: (msg, meta) => log(msg, meta ?? ""),
      info: (msg, meta) => log(msg, meta ?? ""),
      warn: (msg, meta) => log(msg, meta ?? ""),
      error: (msg, meta) => log(msg, meta ?? ""),
    }
  : undefined;

/**
 * A witness on its own ephemeral port. The socket binds before the `Witness` is
 * built because the `/loc/scheme` reply is signed over the URL, and KERIpy dials
 * whatever that reply carries — a placeholder port would be baked in and never
 * reached.
 */
export async function startWitness(opts: { signal?: AbortSignal } = {}): Promise<WitnessEndpoint> {
  const server = createServer();

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, () => resolve());
  });

  const { port } = server.address() as AddressInfo;
  const url = `http://localhost:${port}`;

  const witness = new Witness({
    privateKey: generateKeyPair().privateKey,
    url,
    store: new MemoryStore(),
    logger,
  });

  server.on("request", createListener(witness.fetch));
  opts.signal?.addEventListener("abort", () => server.close(), { once: true });

  return { aid: witness.aid, url, oobi: `${url}/oobi/${witness.aid}` };
}
