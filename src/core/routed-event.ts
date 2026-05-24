import { Attachments, Message } from "../cesr/main.ts";
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

export type RoutedEventBody = QueryEventBody | ReplyEventBody | ExchangeEventBody;

export type RoutedEvent = Message<RoutedEventBody>;

// Shallow type guards: match on `t` only. Structural validation (required
// fields, SAID, signature verification against signer's KEL) happens later.
export function isQuery(m: Message): m is Message<QueryEventBody> {
  return m.body.t === "qry";
}

export function isReply(m: Message): m is Message<ReplyEventBody> {
  return m.body.t === "rpy";
}

export function isExchange(m: Message): m is Message<ExchangeEventBody> {
  return m.body.t === "exn";
}

export function isRoutedEvent(m: Message): m is RoutedEvent {
  return isQuery(m) || isReply(m) || isExchange(m);
}

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
