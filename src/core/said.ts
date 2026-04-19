import { blake3 } from "@noble/hashes/blake3.js";
import { Matter } from "#keri/cesr";

function calculateSaid(event: Record<string, unknown>): string {
  const digest = new Matter({
    code: Matter.Code.Blake3_256,
    raw: blake3
      .create({ dkLen: 32 })
      .update(new TextEncoder().encode(JSON.stringify(event)))
      .digest(),
  });
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
