import { scrypt } from "@noble/hashes/scrypt.js";

export function createSeed(passphrase: string, salt: string): Uint8Array {
  return scrypt(passphrase, salt, { N: 16384, r: 8, p: 1, dkLen: 32 });
}
