import { Attachments, Message } from "../cesr/__main__.ts";
import { DUMMY_VERSION, encodeEvent, formatDate } from "./events.ts";
import { saidify } from "./said.ts";

export interface QueryEventInit {
  dt?: Date;
  r?: string;
  rr?: string;
  q: Record<string, unknown>;
}

export type QueryEventBody = {
  v: string;
  t: "qry";
  d: string;
  dt: string;
  r: string;
  rr: string;
  q: Record<string, unknown>;
};

export interface ReplyEventInit {
  dt?: string;
  r: string;
  a: Record<string, unknown>;
}

export type ReplyEventBody = {
  v: string;
  t: "rpy";
  d: string;
  dt: string;
  r: string;
  a: Record<string, unknown>;
};

export type RoutedEventBody = {
  v: string;
  t: string;
  d: string;
  r: string;
  [key: string]: unknown;
};

export type RoutedEvent = Message<RoutedEventBody>;

export function query(args: QueryEventInit): Message<QueryEventBody> {
  const body = encodeEvent<QueryEventBody>({
    v: DUMMY_VERSION,
    t: "qry",
    d: "",
    dt: formatDate(args.dt ?? new Date()),
    r: args.r ?? "",
    rr: args.rr ?? "",
    q: args.q,
  });

  return new Message(body);
}

export function reply(args: ReplyEventInit): Message<ReplyEventBody> {
  const body = encodeEvent<ReplyEventBody>({
    v: DUMMY_VERSION,
    t: "rpy",
    d: "",
    dt: args.dt ?? formatDate(new Date()),
    r: args.r,
    a: args.a,
  });

  return new Message(body);
}

export interface ExchangeEventInit {
  sender: string;
  recipient?: string;
  p?: string;
  timestamp?: string;
  route: string;
  query?: Record<string, unknown>;
  anchor?: Record<string, unknown>;
  embeds?: Record<string, Message>;
}

export interface ExchangeEmbedding {
  d: string;
  [key: string]: string | Record<string, unknown>;
}

export interface ExchangeEventBody extends Record<string, unknown> {
  v: string;
  t: "exn";
  d: string;
  i: string;
  rp: string;
  p: string;
  dt: string;
  r: string;
  q: Record<string, unknown>;
  a: Record<string, unknown>;
  e: Record<string, string | Record<string, unknown>>;
}

export function exchange(args: ExchangeEventInit): Message<ExchangeEventBody> {
  const embeds: ExchangeEmbedding = { d: "" };
  const attachments = new Attachments();

  for (const [key, message] of Object.entries(args.embeds ?? {})) {
    embeds[key] = message.body;
    attachments.PathedMaterialCouples.push({
      path: `-${["e", key].join("-")}`,
      attachments: message.attachments,
      grouped: true,
    });
  }

  const body = encodeEvent<ExchangeEventBody>({
    v: DUMMY_VERSION,
    t: "exn",
    d: "",
    i: args.sender,
    rp: args.recipient ?? "",
    p: args.p ?? "",
    dt: args.timestamp ?? formatDate(new Date()),
    r: args.route,
    q: args.query ?? {},
    a: args.anchor ?? {},
    e: args.embeds ? saidify(embeds, ["d"]) : {},
  });

  return new Message(body, attachments);
}
