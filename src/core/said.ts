import { blake3 } from "@noble/hashes/blake3.js";
import { cesr } from "../cesr/__main__.ts";

function calculateSaid(event: Record<string, unknown>): string {
  const digest = cesr.crypto.blake3_256(
    blake3
      .create({ dkLen: 32 })
      .update(new TextEncoder().encode(JSON.stringify(event)))
      .digest(),
  );

  return digest.text();
}

export interface SaidArgs {
  labels?: string[];
}

export function saidify<T extends Record<string, unknown>>(event: T, labels?: string[]): T {
  if (!labels?.length) {
    return event;
  }

  const digest = calculateSaid(event);
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(event)) {
    if (labels.includes(key)) {
      result[key] = digest;
    } else {
      result[key] = value;
    }
  }

  return result as T;
}
