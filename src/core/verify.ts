import { ed25519 } from "@noble/curves/ed25519.js";
import { Indexer, Matter } from "cesr";
import { parseThreshold, type Threshold } from "./threshold.ts";

export interface VerifyOptions {
  threshold: Threshold;
  keys: string[];
  sigs: string[];
}

export type VerifyResult =
  | {
      ok: true;
    }
  | {
      ok: false;
      error: string;
    };

function verifySignature(payload: Uint8Array, key: Matter, sig: Indexer | Matter): boolean {
  switch (key.code) {
    case Matter.Code.Ed25519:
    case Matter.Code.Ed25519N:
      // TODO:
      // We can check the code of the signature,
      // but it does not really matter since it will be verified correctly regardless.
      // Anyway, revisit later
      return ed25519.verify(sig.raw, payload, key.raw);
    default:
      throw new Error(`Unsupported key code: ${key.code}`);
  }
}

export function verify(payload: Uint8Array, options: VerifyOptions): VerifyResult {
  const keys = options.keys.map((key) => Matter.parse(key));
  const sigs = options.sigs.map((sig) => Indexer.parse(sig));
  const threshold = parseThreshold(options.threshold, options.keys.length);

  let sum = 0;

  for (let idx = 0; idx < keys.length; idx++) {
    const sig = sigs.find((s) => s.index === idx);
    if (!sig) {
      continue;
    }

    if (!verifySignature(payload, keys[idx], sig)) {
      return { ok: false, error: `Invalid signature for key at index ${idx}` };
    }

    sum += threshold.weights[idx];
  }

  if (sum < threshold.required) {
    return { ok: false, error: `Threshold not met: ${sum} weight provided, but ${threshold.required} required` };
  }

  return { ok: true };
}

export function verifyOrThrow(payload: Uint8Array, options: VerifyOptions): void {
  const result = verify(payload, options);
  if (!result.ok) {
    throw new Error(result.error);
  }
}
