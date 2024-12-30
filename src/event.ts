import { blake3 } from "@noble/hashes/blake3";
import cesr from "./parser/cesr-encoding.ts";
import { MatterCode } from "./parser/codes.ts";

export type DataValue = string | number | boolean | DataObject | DataArray;

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface DataArray extends Array<DataValue> {}

export type DataObject = {
  [x: string]: DataValue;
};

const encoder = new TextEncoder();

function formatSize(size: number) {
  return size.toString(16).padStart(6, "0");
}

function formatVersion(label: "KERI10" | "ACDC10", size: number) {
  return `${label}JSON${formatSize(size)}_`;
}

// const DUMMY_VERSION = "PPPPVVVKKKKBBBB.";
// const DUMMY_LEGACY_VERSION = "PPPPvvKKKKllllll_";

function versify<T extends DataObject>(data: T): T & { v: string } {
  const encoder = new TextEncoder();
  const str = encoder.encode(
    JSON.stringify({
      v: formatVersion("KERI10", 0),
      ...data,
    }),
  );

  const version = formatVersion("KERI10", str.byteLength);

  return {
    v: version,
    ...data,
  };
}

export type Threshold = string | string[];

export interface InceptArgs {
  k: string[];
  kt: Threshold;
  n: string[];
  nt: Threshold;
  b?: string[];
  bt?: string;
}

export function incept(data: InceptArgs) {
  const event = versify({
    t: "icp",
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
