import { blake3 } from "@noble/hashes/blake3";
import cesr from "../parser/cesr-encoding.ts";
import { MatterCode } from "../parser/codes.ts";
import type { DataArray } from "../data-type.ts";
import { versify } from "../parser/version.ts";

export interface InteractArgs {
  i: string;
  s: string;
  p: string;
  a: DataArray;
}

export interface InteractEvent {
  v: string;
  t: "ixn";
  d: string;
  i: string;
  s: string;
  p: string;
  a: DataArray;
}

export function interact(data: InteractArgs): InteractEvent {
  const event = versify({
    t: "ixn" as const,
    d: "#".repeat(44),
    i: data.i,
    s: data.s,
    p: data.p,
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

  return Object.freeze(event);
}
