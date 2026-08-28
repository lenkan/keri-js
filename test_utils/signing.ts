import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, type Message } from "../src/cesr/main.ts";
import type { KeyPair } from "../src/keys/main.ts";

/**
 * Signing helpers shared by the unit tests.
 *
 * `signEvent` is the API consumers should use, but most tests here build a KEL
 * inside a synchronous helper that needs the raw indexed signature. These
 * produce byte-identical output: `Indexer.convert` dispatches to the same
 * `ed25519_sig` constructor.
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
