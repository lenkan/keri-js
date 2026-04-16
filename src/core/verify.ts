import { ed25519 } from "@noble/curves/ed25519.js";
import { Indexer, Matter } from "../cesr/__main__.ts";
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

export function verifySignature(payload: Uint8Array, key: Matter, sig: Uint8Array): boolean {
  switch (key.code) {
    case Matter.Code.Ed25519:
    case Matter.Code.Ed25519N:
      return ed25519.verify(sig, payload, key.raw);
    default:
      throw new Error(`Unsupported key code: ${key.code}`);
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

    if (!verifySignature(payload, keys[idx], sig.raw)) {
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
    if (!verifySignature(payload, keys[idx], sig.raw)) {
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
