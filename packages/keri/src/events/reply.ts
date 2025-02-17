import type { DataObject } from "../data-type.ts";
import { versify } from "../parser/version.ts";
import { saidify } from "./common.ts";

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

  return saidify(event);
}
