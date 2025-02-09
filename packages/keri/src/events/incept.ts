import { blake3 } from "@noble/hashes/blake3";
import cesr from "../parser/cesr-encoding.ts";
import { MatterCode } from "../parser/codes.ts";
import type { DataArray } from "../data-type.ts";
import { versify } from "../parser/version.ts";
import type { Threshold } from "./common.ts";

export interface InceptArgs {
  k: string[];
  kt?: Threshold;
  n?: string[];
  nt?: Threshold;
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

function isTransferable(key: string) {
  const raw = cesr.decode(key);
  switch (raw.code) {
    case MatterCode.ECDSA_256k1N:
    case MatterCode.Ed25519N:
    case MatterCode.Ed448N:
      return false;
    default:
      return true;
  }
}

function resolveBackerThreshold(data: InceptArgs) {
  if (data.bt) {
    return data.bt;
  }

  if (!data.b || data.b.length === 0) {
    return 0;
  }

  if (data.b.length === 1) {
    return 1;
  }

  return data.b.length - 1;
}

export function incept(data: InceptArgs): InceptEvent {
  if (data.k.length === 0) {
    throw new Error("No keys provided in inception event");
  }

  const event = versify({
    t: "icp" as const,
    d: "#".repeat(44),
    i: "#".repeat(44),
    s: "0",
    kt: data.kt ?? data.k.length.toString(),
    k: data.k,
    nt: data.nt ?? data.n?.length.toString() ?? "0",
    n: data.n ?? [],
    bt: resolveBackerThreshold(data).toString(),
    b: data.b ?? [],
    c: [] as string[],
    a: [] as DataArray,
  });

  const encoder = new TextEncoder();
  const transferable = event.k.length > 1 || isTransferable(event.k[0]);

  if (!transferable) {
    event["i"] = event.k[0];
  }

  const raw = encoder.encode(JSON.stringify(event));

  const said = cesr.encode(MatterCode.Blake3_256, blake3.create({ dkLen: 32 }).update(raw).digest());

  event["d"] = said;
  event["i"] = transferable ? said : event["i"];

  return event;
}
