import { blake3 } from "@noble/hashes/blake3.js";
import { encodeText, Matter } from "cesr";

/**
 * The digest committing to a next public key, for the `n` field of an
 * establishment event. Takes the CESR-encoded public key, not raw bytes.
 */
export function nextKeyDigest(publicKey: string): string {
  const digest = Matter.crypto.blake3_256(
    blake3.create({ dkLen: 32 }).update(new TextEncoder().encode(publicKey)).digest(),
  );
  return encodeText(digest);
}
