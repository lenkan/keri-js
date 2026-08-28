import { blake3 } from "@noble/hashes/blake3.js";
import { Matter } from "../cesr/main.ts";
import { nextKeyDigest } from "./digest.ts";
import { ed25519Signer, type Signer } from "./signer.ts";

/** A generated key, usable as its own {@link Signer}. */
export interface KeyPair extends Signer {
  readonly privateKey: Uint8Array;

  /** The commitment to publish under `n` when this is the *next* key. */
  readonly publicKeyDigest: string;
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

  const signer = ed25519Signer(privateKey, { nonTransferable: options?.nonTransferable });

  return { ...signer, privateKey, publicKeyDigest: nextKeyDigest(signer.publicKey) };
}

export function isTransferable(key: string) {
  const raw = Matter.parse(key);
  switch (raw.code) {
    case Matter.Code.ECDSA_256k1N:
    case Matter.Code.Ed25519N:
    case Matter.Code.Ed448N:
      return false;
    default:
      return true;
  }
}
