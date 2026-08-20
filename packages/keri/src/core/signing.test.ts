import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, type Message } from "cesr";
import type { KeyPair } from "./keys.ts";

/**
 * Signing helpers shared by the tests in this submodule.
 *
 * `signEvent` is the API consumers should use, but it is async, and most tests
 * here build a KEL inside a synchronous helper. These produce byte-identical
 * output: `Indexer.convert` dispatches to the same `ed25519_sig` constructor.
 *
 * Lives in a `.test.ts` file so it stays out of the published tarball —
 * `package.json` `files` excludes `src/**\/*.test.ts`.
 */
export function signRaw(payload: Uint8Array, key: Uint8Array, index?: number): string {
  const raw = ed25519.sign(payload, key);

  return index === undefined
    ? encodeText(Matter.crypto.ed25519_sig(raw))
    : encodeText(Indexer.crypto.ed25519_sig(raw, index));
}

/** One indexed signature per key, indexed by position — the order the signing keys are listed in. */
export function signWith(event: Message, keys: KeyPair[]): string[] {
  return keys.map((key, index) => signRaw(event.raw, key.privateKey, index));
}
