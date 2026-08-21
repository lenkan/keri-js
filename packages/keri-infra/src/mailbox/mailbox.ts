import { ed25519 } from "@noble/curves/ed25519.js";
import { type Message, parse } from "cesr";
import { encodeUtf8 } from "cesr/encoding";
import type { ExchangeEventBody, QueryEventBody, ReplyEventBody } from "keri";
import { ed25519Signer, endorse, KeyEvent, KeyEventLog, RoutedEvent, type Signer, signEvent } from "keri";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { KeyEventStorage, MailboxServerStorage } from "../storage/main.ts";

export type MailboxStorageDeps = MailboxServerStorage & KeyEventStorage;

export interface MailboxOptions {
  storage: MailboxStorageDeps;
  privateKey?: Uint8Array;
  url?: string;
  logger?: Logger;
}

export interface MailboxEvent {
  readonly message: Message;
  readonly timestamp: Date;
}

export interface MailboxReply {
  readonly id: number;
  readonly topic: string;
  readonly message: Message;
}

export type EnrollResult = { ok: true; aid: string } | { ok: false; error: string };

/** Stores the inner message of an `exn /fwd` under the recipient and topic it names. */
export function storeForward(
  storage: MailboxServerStorage,
  message: Message<ExchangeEventBody>,
  log: KeriLogger,
): void {
  const { q } = message.body;
  const pre = q.pre as string | undefined;
  const topic = q.topic as string | undefined;

  if (!pre || !topic) {
    log.warn("ignoring forward: missing q.pre or q.topic");
    return;
  }

  const innerMessage = RoutedEvent.embeds(message).evt;
  if (!innerMessage) {
    log.warn("ignoring forward: missing e.evt", { pre, topic });
    return;
  }

  log.debug("saving mailbox entry", { pre, topic });
  storage.saveMailboxEntry(pre, topic, innerMessage);
}

/** Answers a `qry mbx`: entries per queried topic from the given inclusive offset. */
export function* queryMailbox(
  storage: MailboxServerStorage,
  message: Message<QueryEventBody>,
  log: KeriLogger,
): Generator<MailboxReply> {
  const { i, topics } = message.body.q as {
    i?: string;
    topics?: Record<string, number>;
  };

  if (!i || !topics) {
    log.warn("ignoring query: missing q.i or q.topics");
    return;
  }

  log.debug("querying mailbox", { aid: i, topics });
  for (const [topicPath, offset] of Object.entries(topics)) {
    const storageTopic = topicPath.replace(/^\//, "");
    for (const entry of storage.getMailboxEntries(i, storageTopic, offset)) {
      yield { id: entry.id, topic: topicPath, message: entry.message };
    }
  }
}

async function* single(chunk: Uint8Array): AsyncIterable<Uint8Array> {
  yield chunk;
}

/**
 * The `kli mailbox add` contract: the controller POSTs its full KEL and a
 * signed `/end/role/add` naming this mailbox. Everything is verified before
 * anything is stored — the KEL replays, and the rpy must be signed by the
 * KEL's current keys, sealed to its last establishment event.
 */
export async function enroll(
  storage: MailboxStorageDeps,
  mailboxAid: string,
  kel: string,
  rpy: string,
  log: KeriLogger,
): Promise<EnrollResult> {
  let kelLog: KeyEventLog;
  try {
    kelLog = await KeyEventLog.parse(single(encodeUtf8(kel)), { allowPartiallyWitnessed: true });
    if (kelLog.events.length === 0) {
      return { ok: false, error: "The kel field carries no key events" };
    }
  } catch (cause) {
    return { ok: false, error: `Invalid kel: ${cause instanceof Error ? cause.message : String(cause)}` };
  }

  const aid = kelLog.state.identifier;

  let reply: Message<ReplyEventBody> | undefined;
  try {
    for await (const message of parse(rpy)) {
      if (message.body.t === "rpy") {
        reply = message as Message<ReplyEventBody>;
        break;
      }
    }
  } catch (cause) {
    return { ok: false, error: `Invalid rpy: ${cause instanceof Error ? cause.message : String(cause)}` };
  }

  if (!reply) {
    return { ok: false, error: "The rpy field carries no reply message" };
  }

  const { r, a } = reply.body;
  if (r !== "/end/role/add" || a.cid !== aid || a.role !== "mailbox" || a.eid !== mailboxAid) {
    return { ok: false, error: "The rpy must be /end/role/add naming the KEL's AID as cid and this mailbox as eid" };
  }

  const verdict = RoutedEvent.verifyReply(reply, kelLog.state);
  if (!verdict.ok) {
    return { ok: false, error: `Reply verification failed: ${verdict.error}` };
  }

  for (const event of kelLog.events) {
    storage.saveMessage(event);
  }
  storage.saveMessage(reply);

  log.debug("enrolled", { aid });
  return { ok: true, aid };
}

/**
 * OOBI for an enrolled AID, in KERIpy's emit order: the KEL, this mailbox's
 * own `/loc/scheme`, then the stored `/end/role/add` naming this mailbox.
 * Null when the AID is unknown.
 */
export function serveOobi(
  storage: MailboxStorageDeps,
  aid: string,
  self: { aid: string; events: readonly MailboxEvent[] },
): Message[] | null {
  const kel = Array.from(storage.getKeyEvents(aid));
  if (kel.length === 0) {
    return null;
  }

  const endRoles = Array.from(storage.getReplies({ cid: aid, route: "/end/role/add" })).filter(
    (message) => message.body.a.role === "mailbox" && message.body.a.eid === self.aid,
  );

  const location = self.events
    .map((event) => event.message)
    .filter((message) => (message.body as { r?: string }).r === "/loc/scheme");

  return [...kel, ...(endRoles.length > 0 ? location : []), ...endRoles];
}

export class Mailbox {
  readonly #storage: MailboxStorageDeps;
  readonly #kel: KeyEventLog;
  readonly #log: KeriLogger;
  readonly events: readonly MailboxEvent[];

  static async createKEL(signer: Signer): Promise<KeyEventLog> {
    const icp = KeyEvent.incept({ signingKeys: [signer.publicKey], nextKeyDigests: [] });
    signEvent(icp, { signers: [signer] });
    return KeyEventLog.from([icp]);
  }

  get aid(): string {
    return this.#kel.state.identifier;
  }

  static async create(options: MailboxOptions): Promise<Mailbox> {
    const signer = ed25519Signer(options.privateKey ?? ed25519.utils.randomSecretKey(), { nonTransferable: true });
    const kel = await Mailbox.createKEL(signer);
    const aid = kel.state.identifier;

    const events: MailboxEvent[] = [{ message: kel.events[0], timestamp: new Date() }];

    if (options.url) {
      const url = new URL(options.url);
      const scheme = url.protocol.replace(":", "");

      const location = RoutedEvent.reply({
        r: "/loc/scheme",
        a: { eid: aid, scheme, url: options.url },
      });

      const endrole = RoutedEvent.reply({
        r: "/end/role/add",
        a: { cid: aid, role: "mailbox", eid: aid },
      });

      endorse(location, { signers: [signer], state: kel.state });
      endorse(endrole, { signers: [signer], state: kel.state });

      events.push({ message: location, timestamp: new Date() });
      events.push({ message: endrole, timestamp: new Date() });
    }

    return new Mailbox(options, kel, events);
  }

  private constructor(options: MailboxOptions, kel: KeyEventLog, events: MailboxEvent[]) {
    this.#storage = options.storage;
    this.#kel = kel;
    this.#log = new KeriLogger(options.logger);
    this.events = events;
  }

  async *handleMessage(message: Message): AsyncGenerator<MailboxReply> {
    const { t, r } = message.body as { t?: string; r?: string };

    if (t === "exn" && r === "/fwd") {
      this.#log.debug("handling exn /fwd");
      storeForward(this.#storage, message as Message<ExchangeEventBody>, this.#log);
      return;
    }

    if (t === "qry" && r === "mbx") {
      this.#log.debug("handling qry mbx");
      yield* queryMailbox(this.#storage, message as Message<QueryEventBody>, this.#log);
      return;
    }

    this.#log.debug("ignoring message", { t, r });
  }

  enroll(kel: string, rpy: string): Promise<EnrollResult> {
    return enroll(this.#storage, this.aid, kel, rpy, this.#log);
  }

  serveOobi(aid: string): Message[] | null {
    return serveOobi(this.#storage, aid, this);
  }
}
