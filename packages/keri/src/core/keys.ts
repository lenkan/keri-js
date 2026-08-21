import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { encodeText, Matter } from "cesr";
import { nextKeyDigest } from "./digest.ts";

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: string;
  publicKeyDigest: string;
}

export interface GenerateKeyPairOptions {
  /**
   * Derive the private key from this string instead of the CSPRNG, so a test
   * gets the same AID every run.
   *
   * Not a passphrase: a bare blake3 of the UTF-8 bytes, with no salt, no KDF
   * and no work factor. Anything reachable from outside a test suite must use
   * the default.
   */
  insecureSeed?: string;
  nonTransferable?: boolean;
}

export function generateKeyPair(options?: GenerateKeyPairOptions): KeyPair {
  const privateKey = options?.insecureSeed
    ? blake3(new TextEncoder().encode(options.insecureSeed), { dkLen: 32 })
    : crypto.getRandomValues(new Uint8Array(32));

  const rawPublicKey = ed25519.getPublicKey(privateKey);
  const code = options?.nonTransferable ? Matter.Code.Ed25519N : Matter.Code.Ed25519;
  const publicKey = encodeText(new Matter({ code, raw: rawPublicKey }));

  return { privateKey, publicKey, publicKeyDigest: nextKeyDigest(publicKey) };
}
