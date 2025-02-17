import { blake3 } from "@noble/hashes/blake3";
import cesr from "../parser/cesr-encoding.ts";
import { MatterCode } from "../parser/codes.ts";

export interface KeyEvent {
  v: string;
  t: string;
  d: string;
}

export type Threshold = string | string[];

export function formatDate(date: Date) {
  return date.toISOString().replace("Z", "000+00:00");
}

export function calculateSaid(event: KeyEvent) {
  const encoder = new TextEncoder();

  const digest = cesr.encode(
    MatterCode.Blake3_256,
    blake3
      .create({ dkLen: 32 })
      .update(encoder.encode(JSON.stringify(event)))
      .digest(),
  );

  return digest;
}

export function saidify<T extends KeyEvent>(event: T): T {
  const encoder = new TextEncoder();

  const digest = cesr.encode(
    MatterCode.Blake3_256,
    blake3
      .create({ dkLen: 32 })
      .update(encoder.encode(JSON.stringify(event)))
      .digest(),
  );

  event["d"] = digest;

  return { ...event };
}
