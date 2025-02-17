import type { DataObject } from "../data-type.ts";
import { versify } from "../parser/version.ts";
import { calculateSaid, formatDate } from "./common.ts";

export interface QueryEvent {
  v: string;
  t: "qry";
  d: string;
  dt: string;
  r: string;
  rr: string;
  q: DataObject;
}

export interface QueryEventArgs {
  dt?: Date;
  r?: string;
  rr?: string;
  q: DataObject;
}

export function query(args: QueryEventArgs): QueryEvent {
  const event = versify({
    t: "qry" as const,
    d: "#".repeat(44),
    dt: formatDate(args.dt ?? new Date()),
    r: args.r ?? "",
    rr: args.rr ?? "",
    q: args.q,
  });

  const digest = calculateSaid(event);

  event["d"] = digest;

  return event;
}
