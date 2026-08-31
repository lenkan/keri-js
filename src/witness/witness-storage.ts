import { decodeUtf8, encodeUtf8, Indexer, Message } from "../cesr/main.ts";
import type { KeyEventBody, ReplyEventBody } from "../main.ts";
import { decodeMessage, encodeMessage } from "./message-codec.ts";
import type { Store } from "./store.ts";

/** Newest entries retained per (pre, topic). See `#prune`. */
const MAILBOX_RETENTION = 1000;

/** Stale entries removed per deposit, so a backlog drains over several writes rather than in one. */
const PRUNE_BATCH = 8;

/**
 * Ordinals are zero-padded so that lexical key order matches numeric order —
 * `scan` is the only ordering there is.
 */
const ORDINAL_WIDTH = 16;

/** Signature indices, padded for the same reason as ordinals. */
const INDEX_WIDTH = 4;

/**
 * Ordinals tried before a deposit gives up. Each loss means another writer took
 * the slot, so exhausting this many in a row is contention no retry budget
 * fixes — better to fail loudly than to keep spinning while the caller waits.
 */
const ORDINAL_ATTEMPTS = 16;

/**
 * The parts an event is stored in, ordered so that a single ascending scan hands
 * them back with the body first. KERIpy keeps the same split across LMDB
 * sub-databases — `evts` for the body, `sigs` and `wigs` as dupsort tables, and
 * `dtss` for the first-seen stamp.
 */
const Part = { body: "0", sig: "1", wig: "2", dt: "3" } as const;

export interface MailboxEntry {
  /** Dense per-(pre, topic) ordinal starting at 0 — what KERIpy calls `fn` and the SSE `id:` field carries. */
  id: number;
  message: Message;
}

/** KERIpy names the topic bare on a deposit (`credential`) and as a path on a poll (`/credential`). */
export function normalizeTopic(topic: string): string {
  return topic.replace(/^\//, "");
}

function ordinal(value: number): string {
  return value.toString(16).padStart(ORDINAL_WIDTH, "0");
}

function readOrdinal(key: string, prefix: string): number {
  return parseInt(key.slice(prefix.length), 16);
}

function index(value: number): string {
  return value.toString(16).padStart(INDEX_WIDTH, "0");
}

const kelPrefix = (aid: string) => `kel:${aid}:`;
const eventPrefix = (aid: string, sn: string, digest: string) =>
  `${kelPrefix(aid)}${ordinal(parseInt(sn, 16))}:${digest}:`;
const roleKey = (cid: string, role: string, eid: string) => `end:${cid}:${role}:${eid}`;
const mailboxPrefix = (pre: string, topic: string) => `mbx:${pre}:${normalizeTopic(topic)}:`;

/** An event's parts as they come back off a scan, before being reassembled. */
interface EventParts {
  sn: string;
  digest: string;
  body?: string;
  dt?: string;
  sigs: string[];
  wigs: string[];
}

function assign(parts: EventParts, part: string, value: string): void {
  switch (part) {
    case Part.body:
      parts.body = value;
      break;
    case Part.dt:
      parts.dt = value;
      break;
    case Part.sig:
      parts.sigs.push(value);
      break;
    case Part.wig:
      parts.wigs.push(value);
      break;
  }
}

function reassemble(parts: EventParts): Message<KeyEventBody> | null {
  if (parts.body === undefined) {
    return null;
  }

  const message = Message.parse(encodeUtf8(parts.body)) as Message<KeyEventBody> | null;
  if (message === null) {
    return null;
  }

  message.attachments = {
    ControllerIdxSigs: parts.sigs,
    WitnessIdxSigs: parts.wigs,
    FirstSeenReplayCouples: [{ fnu: parts.sn, dt: new Date(parts.dt ?? 0) }],
  };
  return message;
}

export class WitnessStorage {
  readonly #store: Store;

  constructor(store: Store) {
    this.#store = store;
  }

  /**
   * The body under its own digest, each signature under its own index, and the
   * first-seen stamp beside them — never one blob. Every write is therefore an
   * idempotent put at a key nothing else claims, so re-receipting an event or
   * two witnesses reporting at once cannot lose anything: there is no state to
   * read, modify and write back.
   */
  async saveEvent(message: Message<KeyEventBody>, firstSeen: Date): Promise<void> {
    const { i, s, d } = message.body;
    const prefix = eventPrefix(i, s, d);

    // Keyed by the index the signature itself carries, never by its position in
    // this message. A receipt may carry any subset in any order, so a position
    // would let a later partial set overwrite a different signer's signature.
    const signatures = (part: string, sigs: readonly string[]) =>
      sigs.map((sig) => this.#store.put(`${prefix}${part}:${index(Indexer.parse(sig).index)}`, sig));

    // Disjoint keys, none of them read-modify-write, and no reader may scan a
    // prefix while it is being written — so the order these land in is nobody's
    // business, and serializing them would cost a round trip apiece.
    await Promise.all([
      this.#store.put(`${prefix}${Part.body}`, decodeUtf8(message.raw)),
      // First seen has to mean first: a replayed receipt of an event already
      // held would otherwise stamp it again and walk the time forward. Losing
      // that race is the correct outcome, so the result is not worth checking.
      this.#store.create(`${prefix}${Part.dt}`, firstSeen.toISOString()),
      ...signatures(Part.sig, message.attachments.ControllerIdxSigs),
      ...signatures(Part.wig, message.attachments.WitnessIdxSigs),
    ]);
  }

  /**
   * A witness signature lands at its own backer index, so a receipt from another
   * witness adds a key rather than rewriting the event. This is the write that
   * used to be a read-merge-write, and the reason two receipts arriving together
   * could drop one of themselves.
   */
  async addWitnessSignature(aid: string, sn: string, digest: string, at: number, sig: string): Promise<void> {
    await this.#store.put(`${eventPrefix(aid, sn, digest)}${Part.wig}:${index(at)}`, sig);
  }

  /**
   * The accepted chain, one event per sequence number.
   *
   * Two digests at the same sn means duplicity. Both are kept — that pair is the
   * evidence — but only the one seen first is replayed, which is what KERI says
   * an accepted KEL is. Scan order groups them together, so the choice is made
   * as the sn boundary goes by rather than by holding the log in memory.
   */
  async *getKeyEvents(aid: string): AsyncGenerator<Message<KeyEventBody>> {
    let earliest: EventParts | null = null;

    for await (const parts of this.#scanEvents(aid)) {
      if (earliest !== null && parts.sn !== earliest.sn) {
        const message = reassemble(earliest);
        if (message) {
          yield message;
        }
        earliest = null;
      }

      // Scan order is digest-ascending within an sn, so a strict comparison
      // leaves the first-stamped one standing and breaks ties by digest.
      if (earliest === null || (parts.dt ?? "") < (earliest.dt ?? "")) {
        earliest = parts;
      }
    }

    if (earliest !== null) {
      const message = reassemble(earliest);
      if (message) {
        yield message;
      }
    }
  }

  /** Every stored digest at a sequence number. More than one is duplicity. */
  async digestsAt(aid: string, sn: string): Promise<string[]> {
    const digests: string[] = [];
    for await (const parts of this.#scanEvents(aid, sn)) {
      if (parts.body !== undefined) {
        digests.push(parts.digest);
      }
    }
    return digests;
  }

  /** Groups a scan into one `EventParts` per (sn, digest), in key order. */
  async *#scanEvents(aid: string, sn?: string): AsyncGenerator<EventParts> {
    const prefix = sn === undefined ? kelPrefix(aid) : `${kelPrefix(aid)}${ordinal(parseInt(sn, 16))}:`;
    let current: EventParts | null = null;

    for await (const entry of this.#store.scan(prefix)) {
      const [sn, digest, part] = entry.key.slice(kelPrefix(aid).length).split(":");
      if (sn === undefined || digest === undefined || part === undefined) {
        continue;
      }

      if (current !== null && (current.sn !== sn || current.digest !== digest)) {
        yield current;
        current = null;
      }
      current ??= { sn, digest, sigs: [], wigs: [] };

      assign(current, part, entry.value);
    }

    if (current !== null) {
      yield current;
    }
  }

  /**
   * A `rpy` supersedes by `dt`, and `kli ends add` stamps a fresh one per run.
   * The key is the (cid, role, eid) identity rather than the SAID, so a
   * re-registration replaces its predecessor instead of accumulating beside it.
   */
  async putRole(message: Message<ReplyEventBody>): Promise<void> {
    const { cid, role, eid } = message.body.a as { cid: string; role: string; eid: string };
    await this.#store.put(roleKey(cid, role, eid), encodeMessage(message));
  }

  async getRole(cid: string, role: string, eid: string): Promise<Message<ReplyEventBody> | null> {
    const value = await this.#store.get(roleKey(cid, role, eid));
    return value === null ? null : (decodeMessage(value) as Message<ReplyEventBody>);
  }

  /**
   * The ordinal is read from the tail and written one past it, which two
   * concurrent deposits would both resolve to the same value, so the slot is
   * claimed rather than written and a loss moves up to the next one. On a store
   * with one writer the first attempt always wins and this is a plain insert.
   */
  async saveMailboxEntry(pre: string, topic: string, message: Message): Promise<void> {
    const prefix = mailboxPrefix(pre, topic);
    const value = encodeMessage(message);
    const tail = await this.#store.last(prefix);
    let next = tail === null ? 0 : readOrdinal(tail, prefix) + 1;

    for (let attempt = 0; attempt < ORDINAL_ATTEMPTS; attempt++) {
      if (await this.#store.create(`${prefix}${ordinal(next)}`, value)) {
        await this.#prune(prefix, next);
        return;
      }
      next++;
    }

    throw new Error(`Could not claim a mailbox ordinal for ${pre} after ${ORDINAL_ATTEMPTS} attempts`);
  }

  // `offset` is the inclusive start ordinal — KERIpy's poller sends
  // lastSeenId + 1 and expects that entry to be the first one back.
  async *getMailboxEntries(pre: string, topic: string, offset: number): AsyncGenerator<MailboxEntry> {
    const prefix = mailboxPrefix(pre, topic);
    for await (const entry of this.#store.scan(prefix, { start: `${prefix}${ordinal(offset)}` })) {
      yield { id: readOrdinal(entry.key, prefix), message: decodeMessage(entry.value) };
    }
  }

  /**
   * Nothing acknowledges a mailbox entry — the cursor lives on the client — so
   * without a cap a mailbox grows forever.
   *
   * The newest entry is never pruned: the next ordinal is derived from the
   * surviving tail, so emptying a (pre, topic) would restart the sequence at 0
   * and silently invalidate every client cursor pointing past it.
   */
  async #prune(prefix: string, latest: number): Promise<void> {
    const cutoff = latest - MAILBOX_RETENTION;
    if (cutoff < 0) {
      return;
    }

    // Collected before deleting: `scan` may not be read while the same keys are
    // being written, and an adapter is free to back it with a live cursor.
    const stale: string[] = [];
    for await (const entry of this.#store.scan(prefix, { limit: PRUNE_BATCH })) {
      if (readOrdinal(entry.key, prefix) > cutoff) {
        break;
      }
      stale.push(entry.key);
    }

    await Promise.all(stale.map((key) => this.#store.delete(key)));
  }
}
