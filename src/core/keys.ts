import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { encodeText, Matter } from "#keri/cesr";

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
  const code = options?.nonTransferable ? Matter.Code.Ed25519N : Matter.Code.Ed25519;
  const publicKey = encodeText(new Matter({ code, raw: rawPublicKey }));

  const publicKeyDigest = encodeText(
    new Matter({
      code: Matter.Code.Blake3_256,
      raw: blake3.create({ dkLen: 32 }).update(new TextEncoder().encode(publicKey)).digest(),
    }),
  );

  return { privateKey, publicKey, publicKeyDigest };
}
