import { blake3 } from "@noble/hashes/blake3.js";
import { Matter } from "#keri/cesr";

export function digest(input: string): string {
  const digest = Matter.crypto.blake3_256(
    blake3.create({ dkLen: 32 }).update(new TextEncoder().encode(input)).digest(),
  );
  return digest.text();
}
