import { blake3 } from "@noble/hashes/blake3";
import cesr from "../parser/cesr-encoding.ts";
import { MatterCode } from "../parser/codes.ts";
import type { DataObject } from "../data-type.ts";
import { versify } from "../parser/version.ts";

export interface ReplyArgs {
  dt?: string;
  r: string;
  a: DataObject;
}

export interface ReplyEvent {
  v: string;
  t: "rpy";
  d: string;
  dt: string;
  r: string;
  a: DataObject;
}

export function reply(data: ReplyArgs): ReplyEvent {
  const event = versify({
    t: "rpy" as const,
    d: "#".repeat(44),
    dt: data.dt ?? new Date().toISOString(),
    r: data.r,
    a: data.a,
  });

  const encoder = new TextEncoder();
  const digest = cesr.encode(
    MatterCode.Blake3_256,
    blake3
      .create({ dkLen: 32 })
      .update(encoder.encode(JSON.stringify(event)))
      .digest(),
  );

  event["d"] = digest;

  return event;
}
