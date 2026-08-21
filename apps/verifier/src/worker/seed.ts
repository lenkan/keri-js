import { decodeBase64Url } from "cesr/encoding";

export function decodeSeed(value: string): Uint8Array {
  // `openssl rand -base64 32` is the obvious way to mint this, and it emits
  // padded standard base64. decodeBase64Url consumes the padding as data rather
  // than rejecting it, so the seed silently arrives 33 bytes long.
  const normalized = value.trim().replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  const bytes = decodeBase64Url(normalized);

  if (bytes.length !== 32) {
    throw new Error(`VERIFIER_SEED must decode to 32 bytes, got ${bytes.length}`);
  }

  return bytes;
}
