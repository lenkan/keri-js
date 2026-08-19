/** biome-ignore-all lint/suspicious/noConsole: server entrypoint */
import { createVerifierRouter, type SessionStore, Verifier } from "@keri-js/infra/verifier";
import { decodeBase64Url } from "cesr/encoding";

const port = Number.parseInt(Deno.env.get("PORT") ?? "3002", 10);
const url = Deno.env.get("VERIFIER_URL") ?? `http://localhost:${port}`;

// The AID has to survive restarts and redeploys, or every published OOBI goes
// stale. A stored seed keeps it stable without a key derivation on cold start.
const seed = Deno.env.get("VERIFIER_SEED");
const privateKey = seed ? decodeSeed(seed) : undefined;

if (!seed) {
  console.warn("VERIFIER_SEED is not set, using an ephemeral identity for this process only");
}

const kv = await Deno.openKv();

const sessions: SessionStore = {
  async get(token) {
    const entry = await kv.get<string>(["session", token]);
    return entry.value;
  },
  async put(token, cesr, ttlMs) {
    await kv.set(["session", token], cesr, { expireIn: ttlMs });
  },
};

const verifier = new Verifier({ privateKey, url });
const router = createVerifierRouter(verifier, sessions, { logger: console });

Deno.serve({ port, onListen: () => banner() }, router);

function decodeSeed(value: string): Uint8Array {
  const bytes = decodeBase64Url(value);

  if (bytes.length !== 32) {
    throw new Error(`VERIFIER_SEED must decode to 32 bytes, got ${bytes.length}`);
  }

  return bytes;
}

function banner(): void {
  console.log(
    ["", "Verifier running at:", `  ${url}`, `  ${verifier.oobi}`, "", `AID: ${verifier.aid}`, ""].join("\n"),
  );
}
