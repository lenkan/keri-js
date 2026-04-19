import { ed25519 } from "@noble/curves/ed25519.js";
import { Indexer, Matter } from "#keri/cesr";

export interface SignOptions {
  key: Uint8Array;
  index?: number;
}

export function sign(payload: Uint8Array, options: SignOptions): string {
  const signature = ed25519.sign(payload, options.key);

  if (options.index !== undefined && options.index !== null) {
    return Indexer.crypto.ed25519_sig(signature, options.index).text();
  }

  return Matter.crypto.ed25519_sig(signature).text();
}
