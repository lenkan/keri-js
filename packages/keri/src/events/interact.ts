import type { DataArray } from "../data-type.ts";
import { versify } from "../parser/version.ts";
import { calculateSaid } from "./common.ts";

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

  const digest = calculateSaid(event);

  event["d"] = digest;

  return Object.freeze(event);
}
