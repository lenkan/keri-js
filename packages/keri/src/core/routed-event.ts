import { Attachments, Message, type MessageBody } from "cesr";
import { DUMMY_VERSION, encodeEvent, formatDate } from "./events.ts";
import { saidify } from "./said.ts";

export interface QueryEventArgs {
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

export interface ReplyEventArgs {
  dt?: Date;
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

export function query(args: QueryEventArgs): Message<QueryEventBody> {
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

export function reply(args: ReplyEventArgs): Message<ReplyEventBody> {
  const body = encodeEvent<ReplyEventBody>({
    v: DUMMY_VERSION,
    t: "rpy",
    d: "",
    dt: formatDate(args.dt ?? new Date()),
    r: args.r,
    a: args.a,
  });

  return new Message(body);
}

export interface ExchangeEventArgs {
  sender: string;
  recipient?: string;
  p?: string;
  timestamp?: Date;
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

export const IPEX_GRANT_ROUTE = "/ipex/grant";
export const CHALLENGE_RESPONSE_ROUTE = "/challenge/response";

export function exchange(args: ExchangeEventArgs): Message<ExchangeEventBody> {
  const block: ExchangeEmbedding = { d: "" };
  const attachments = new Attachments();

  for (const [key, message] of Object.entries(args.embeds ?? {})) {
    block[key] = message.body;
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
    dt: formatDate(args.timestamp ?? new Date()),
    r: args.route,
    q: args.query ?? {},
    a: args.anchor ?? {},
    e: args.embeds ? saidify(block, ["d"]) : {},
  });

  return new Message(body, attachments);
}

/**
 * The messages an `exn` carries in `e`, each rejoined with the attachments
 * `exchange` detached to `-e-<label>`. Without them a granted ACDC has no
 * issuance seal and its anchoring event no signatures.
 *
 * `e.d` is the SAID of the embed block rather than a message, so the object
 * check skips it.
 */
export function embeds(message: Message<ExchangeEventBody>): Record<string, Message> {
  const result: Record<string, Message> = {};

  for (const [label, body] of Object.entries(message.body.e ?? {})) {
    if (!body || typeof body !== "object") {
      continue;
    }

    const couple = message.attachments.PathedMaterialCouples.find((c) => c.path === `-e-${label}`);
    result[label] = new Message(body as MessageBody, couple?.attachments);
  }

  return result;
}

const ROUTED_EVENT_TYPES = new Set(["exn", "qry", "rpy"]);

export function isRoutedEvent(message: Message): message is Message<RoutedEventBody> {
  return ROUTED_EVENT_TYPES.has(message.body.t as string);
}
