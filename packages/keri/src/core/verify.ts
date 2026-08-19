import { ed25519 } from "@noble/curves/ed25519.js";
import { Indexer, Matter } from "cesr";
import { parseThreshold, type Threshold } from "./threshold.ts";

export interface VerifyOptions {
  threshold: Threshold;
  keys: string[];
  sigs: string[]; // Indexer-encoded; sig.index identifies which key it signs for
}

export type VerifyResult =
  | {
      ok: true;
      error?: null;
    }
  | {
      ok: false;
      error: string;
    };

function verifyRaw(payload: Uint8Array, key: Matter, sig: Uint8Array): boolean {
  switch (key.code) {
    case Matter.Code.Ed25519:
    case Matter.Code.Ed25519N:
      return ed25519.verify(sig, payload, key.raw);
    default:
      throw new Error(`Unsupported key code: ${key.code}`);
  }
}

/**
 * Check one unindexed signature against one public key, both CESR-encoded.
 *
 * Returns a result rather than throwing so an unsupported key code in a stream
 * is reported for that message instead of aborting the whole pass.
 */
export function verifySignature(payload: Uint8Array, publicKey: string, signature: string): VerifyResult {
  let key: Matter;
  let sig: Matter;

  try {
    key = Matter.parse(publicKey);
    sig = Matter.parse(signature);
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }

  switch (key.code) {
    case Matter.Code.Ed25519:
    case Matter.Code.Ed25519N:
      return ed25519.verify(sig.raw, payload, key.raw) ? { ok: true } : { ok: false, error: "Invalid signature" };
    default:
      return { ok: false, error: `Unsupported key code: ${key.code}` };
  }
}

export function verifyThreshold(payload: Uint8Array, options: VerifyOptions): VerifyResult {
  const keys = options.keys.map((key) => Matter.parse(key));
  const sigs = options.sigs.map((sig) => Indexer.parse(sig));
  const threshold = parseThreshold(options.threshold, options.keys.length);

  let sum = 0;

  for (let idx = 0; idx < keys.length; idx++) {
    const sig = sigs.find((s) => s.index === idx);
    if (!sig) {
      continue;
    }

    if (!verifyRaw(payload, keys[idx], sig.raw)) {
      return { ok: false, error: `Invalid signature for key at index ${idx}` };
    }

    sum += threshold.weights[idx];
  }

  if (sum < threshold.required) {
    return { ok: false, error: `Threshold not met: ${sum} weight provided, but ${threshold.required} required` };
  }

  return { ok: true };
}

export function verifyThresholdOrThrow(payload: Uint8Array, options: VerifyOptions): void {
  const result = verifyThreshold(payload, options);
  if (!result.ok) {
    throw new Error(result.error);
  }
}

/**
 * Validates that every signature present is cryptographically valid for its key,
 * but does NOT check that the threshold is met.
 */
export function verifySignatures(payload: Uint8Array, options: VerifyOptions): VerifyResult {
  const keys = options.keys.map((key) => Matter.parse(key));
  const sigs = options.sigs.map((sig) => Indexer.parse(sig));

  for (let idx = 0; idx < keys.length; idx++) {
    const sig = sigs.find((s) => s.index === idx);
    if (!sig) continue;
    if (!verifyRaw(payload, keys[idx], sig.raw)) {
      return { ok: false, error: `Invalid signature for key at index ${idx}` };
    }
  }

  return { ok: true };
}

export function verifySignaturesOrThrow(payload: Uint8Array, options: VerifyOptions): void {
  const result = verifySignatures(payload, options);
  if (!result.ok) {
    throw new Error(result.error);
  }
}
