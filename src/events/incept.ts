import { blake3 } from "@noble/hashes/blake3";
import cesr from "../parser/cesr-encoding.ts";
import { MatterCode } from "../parser/codes.ts";
import type { DataArray } from "../data-type.ts";
import { versify } from "../parser/version.ts";
import type { Threshold } from "./common.ts";

export interface InceptArgs {
  k: string[];
  kt: Threshold;
  n: string[];
  nt: Threshold;
  b?: string[];
  bt?: string;
}

export interface InceptEvent {
  v: string;
  t: "icp";
  d: string;
  i: string;
  s: string;
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  b: string[];
  c: string[];
  a: DataArray;
}

export function incept(data: InceptArgs): InceptEvent {
  const event = versify({
    t: "icp" as const,
    d: "#".repeat(44),
    i: "#".repeat(44),
    s: "0",
    kt: data.kt,
    k: data.k,
    nt: data.nt,
    n: data.n,
    bt: data.bt ?? "0",
    b: data.b ?? [],
    c: [] as string[],
    a: [] as DataArray,
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
  event["i"] = digest;

  return event;
}
