import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { cesr } from "#keri/cesr";

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: string;
  publicKeyDigest: string;
}

export interface GenerateKeyPairOptions {
  seed?: string;
  nonTransferable?: boolean;
}

export function generateKeyPair(options?: GenerateKeyPairOptions): KeyPair {
  const privateKey = options?.seed
    ? blake3(new TextEncoder().encode(options.seed), { dkLen: 32 })
    : crypto.getRandomValues(new Uint8Array(32));

  const rawPublicKey = ed25519.getPublicKey(privateKey);
  const publicKey = options?.nonTransferable
    ? cesr.crypto.ed25519N(rawPublicKey).text()
    : cesr.crypto.ed25519(rawPublicKey).text();

  const publicKeyDigest = cesr.crypto
    .blake3_256(blake3.create({ dkLen: 32 }).update(new TextEncoder().encode(publicKey)).digest())
    .text();

  return { privateKey, publicKey, publicKeyDigest };
}
