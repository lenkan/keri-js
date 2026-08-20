import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter } from "cesr";

/**
 * Signing helper shared by the tests in this submodule.
 *
 * These tests build fixture events synchronously, so they cannot use the async
 * `signEvent`/`ed25519Signer` that consumers should reach for. The output is
 * byte-identical to both.
 */
export function sign(payload: Uint8Array, options: { key: Uint8Array; index?: number }): string {
  const raw = ed25519.sign(payload, options.key);

  return options.index === undefined
    ? encodeText(Matter.crypto.ed25519_sig(raw))
    : encodeText(Indexer.crypto.ed25519_sig(raw, options.index));
}
