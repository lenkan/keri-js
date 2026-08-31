import { encodeText, Indexer, Matter, Message } from "../cesr/main.ts";
import {
  type ExchangeEventBody,
  ed25519Signer,
  endorse,
  KeyEvent,
  type KeyEventBody,
  KeyEventLog,
  type KeyState,
  type QueryEventBody,
  type ReceiptEventBody,
  type ReplyEventBody,
  RoutedEvent,
  type Signer,
  signEvent,
} from "../main.ts";
import { type Logger, logger } from "./logger.ts";
import type { Store } from "./store.ts";
import { WitnessError } from "./witness-error.ts";
import { createRouter } from "./witness-router.ts";
import { normalizeTopic, WitnessStorage } from "./witness-storage.ts";

export interface WitnessOptions {
  /** Seed for the witness's own key. Its AID is the non-transferable public key derived from this. */
  privateKey: Uint8Array;
  url?: string;
  store: Store;
  logger?: Logger;

  /**
   * Stamped into the `/loc/scheme` and `/end/role/add` replies. Fixing it at
   * provisioning time is what keeps the OOBI byte-stable: a fresh `new Date()`
   * per construction would change their SAIDs on every request.
   */
  dt?: Date;
}

export interface WitnessEvent {
  readonly message: Message;
  readonly timestamp: Date;
}

export interface MailboxReply {
  readonly id: number;
  readonly topic: string;
  readonly message: Message;
}

const MAILBOX_ROLE_ROUTE = "/end/role/add";

/** Controllers whose key state is held between requests. */
const KEY_STATE_CACHE = 512;

/**
 * KERIpy's topic set, normalized. Retention is per-(pre, topic) and `q.topic` on
 * a deposit is sender-chosen, so accepting an open-ended topic space hands the
 * sender a fresh retention budget per invented name — the cap would bound no
 * amount of storage at all.
 */
const MAILBOX_TOPICS = new Set([
  "receipt",
  "replay",
  "reply",
  "multisig",
  "credential",
  "delegate",
  "challenge",
  "oobi",
  "notification",
]);

export class Witness {
  readonly events: readonly WitnessEvent[];

  /**
   * So the witness itself is what a Web-standard runtime expects: `export
   * default witness`, `Deno.serve(witness)`. An own property rather than a
   * prototype method, so destructuring it off does not lose the binding.
   */
  readonly fetch: (request: Request) => Promise<Response>;

  readonly #storage: WitnessStorage;

  /**
   * The load, not its result. A write only has to delete the entry, and doing so
   * mid-flight drops the pending load with it rather than letting it settle into
   * a value that predates the write. Concurrent reads of one AID also share a
   * single replay, which caching the resolved value could not do.
   */
  readonly #states = new Map<string, Promise<KeyState | null>>();
  readonly #signer: Signer;
  readonly #kel: KeyEventLog;
  readonly #log: Logger;

  get aid() {
    return this.#kel.state.identifier;
  }

  constructor(options: WitnessOptions) {
    const signer = ed25519Signer(options.privateKey, { nonTransferable: true });

    const icp = KeyEvent.incept({ signingKeys: [signer.publicKey], nextKeyDigests: [] });
    signEvent(icp, { signers: [signer] });
    const kel = KeyEventLog.from([icp]);

    const aid = kel.state.identifier;
    const dt = options.dt ?? new Date();
    const events: WitnessEvent[] = [{ message: kel.events[0], timestamp: dt }];

    if (options.url) {
      // Trailing slash stripped, because a peer joins this with a path: KERIpy
      // would dial `//receipts`, which matches no route here, and the receipts
      // simply never arrive. The URL is signed into controller KELs, so a
      // deployment that gets it wrong cannot correct it afterwards.
      const url = options.url.replace(/\/+$/, "");
      const scheme = new URL(url).protocol.replace(":", "");
      const location = RoutedEvent.reply({ dt, r: "/loc/scheme", a: { eid: aid, scheme, url } });
      const endrole = RoutedEvent.reply({ dt, r: "/end/role/add", a: { cid: aid, role: "controller", eid: aid } });

      for (const message of [location, endrole]) {
        endorse(message, { signers: [signer], state: kel.state });
        events.push({ message, timestamp: dt });
      }
    }

    this.#storage = new WitnessStorage(options.store);
    this.#signer = signer;
    this.#kel = kel;
    this.#log = logger(options.logger);
    this.events = events;
    this.fetch = createRouter(this, { logger: options.logger });
  }

  async receipt(message: Message<KeyEventBody>): Promise<Message<ReceiptEventBody>> {
    const body = message.body;

    if (typeof body.i !== "string" || typeof body.d !== "string" || typeof body.s !== "string") {
      this.#log.warn("rejecting receipt: missing required fields i/d/s");
      throw new WitnessError("Missing required fields i, d, s");
    }

    if (message.attachments.ControllerIdxSigs.length === 0) {
      this.#log.warn("rejecting receipt: no controller signatures", { aid: body.i, s: body.s, d: body.d });
      throw new WitnessError("Missing controller signatures");
    }

    let kel = await this.#loadKel(body.i);

    try {
      kel = kel.append(message, { allowPartiallyWitnessed: true });
    } catch (error) {
      if (error instanceof Error) {
        this.#log.warn("rejecting receipt: KEL append failed", {
          aid: body.i,
          s: body.s,
          d: body.d,
          error: error.message,
        });
        throw new WitnessError(`Failed to append message to KEL: ${error.message}`);
      }
    }

    const witnessIndex = kel.state.backers.indexOf(this.aid);
    if (witnessIndex < 0) {
      this.#log.warn("rejecting receipt: not a backer for this AID", { aid: body.i, s: body.s, d: body.d });
      throw new WitnessError("Witness is not a backer for this AID");
    }

    this.#log.debug("issuing receipt", { aid: body.i, s: body.s, d: body.d });

    // No `backers`, so the receipt carries a NonTransReceiptCouple naming this
    // witness — the form a controller expects back. `applyReceipt` then resolves
    // that couple against the backer list into the indexed signature the stored
    // event carries.
    const receipt = KeyEvent.receipt(message, { signers: [this.#signer] });

    const storedMessage = new Message(message.body, {
      ControllerIdxSigs: message.attachments.ControllerIdxSigs,
    });
    KeyEvent.applyReceipt(storedMessage, receipt, kel.state.backers);

    await this.#save(storedMessage);

    return receipt;
  }

  /**
   * The intake dispatch. In KERIpy a witness is also a mailbox, so `POST /`
   * carries three different things: cross-witness receipts, `exn /fwd`
   * deposits, and `qry mbx` polls. Only the poll produces a response body.
   *
   * Eager, not a generator: the receipt and deposit branches are side effects,
   * and a lazy result would skip them for any caller that ignores the return.
   */
  async handleMessage(message: Message): Promise<MailboxReply[]> {
    const { t, r } = message.body as { t?: string; r?: string };

    if (t === "rct") {
      await this.#handleReceipt(message);
      return [];
    }

    if (t === "exn" && r === "/fwd") {
      await this.#storeForward(message as Message<ExchangeEventBody>);
      return [];
    }

    if (t === "qry" && r === "mbx") {
      return this.#queryMailbox(message as Message<QueryEventBody>);
    }

    if (t === "rpy" && r === MAILBOX_ROLE_ROUTE) {
      await this.#storeMailboxRole(message as Message<ReplyEventBody>);
      return [];
    }

    this.#log.debug("ignoring message", { t, r });
    return [];
  }

  async #handleReceipt(message: Message): Promise<void> {
    const body = message.body as KeyEventBody;

    if (typeof body.i !== "string" || typeof body.d !== "string") {
      this.#log.warn("ignoring receipt: missing i/d");
      return;
    }

    // TODO: This should only be for the event that is this receipt
    const kel = await this.#loadKel(body.i);

    if (kel.events.length === 0) {
      this.#log.debug("ignoring receipt: no events stored for aid", { aid: body.i, d: body.d });
      return;
    }

    if (!kel.state.backers.includes(this.aid)) {
      this.#log.debug("ignoring receipt: not a backer", { aid: body.i, d: body.d });
      return;
    }

    const storedEvent = kel.events.find((event) => event.body.d === body.d);
    if (!storedEvent) {
      this.#log.debug("ignoring receipt: no matching stored event", { aid: body.i, d: body.d });
      return;
    }

    // Each signature goes to its own backer index, so this adds keys rather than
    // rewriting the event. Two witnesses reporting at the same moment write
    // different keys and neither can lose the other's.
    const writes = message.attachments.NonTransReceiptCouples.flatMap((couple) => {
      const at = kel.state.backers.indexOf(couple.prefix);
      if (at === -1) {
        return [];
      }
      const sig = encodeText(Indexer.convert(Matter.parse(couple.sig), at));
      return [this.#storage.addWitnessSignature(body.i, storedEvent.body.s, body.d, at, sig)];
    });

    await Promise.all(writes);

    this.#log.debug("stored witness sigs", { aid: body.i, d: body.d, count: writes.length });
    this.#invalidate(body.i);
  }

  /**
   * Records a controller authorizing this witness to hold its mailbox.
   *
   * KERIpy's sender reads this role off the *recipient's* OOBI to decide between
   * a direct send and an `exn /fwd` deposit, so without storing and later serving
   * it the mailbox is never addressed at all. `kli ends add --role mailbox`
   * POSTs it here.
   */
  async #storeMailboxRole(message: Message<ReplyEventBody>): Promise<void> {
    const { a } = message.body;
    const cid = a.cid as string | undefined;

    if (a.eid !== this.aid || a.role !== "mailbox") {
      this.#log.debug("ignoring end role: not a mailbox role for this witness", { role: a.role, eid: a.eid });
      return;
    }

    if (cid === undefined) {
      this.#log.warn("ignoring end role: missing a.cid");
      return;
    }

    const state = await this.#keyState(cid);
    if (!state?.backers.includes(this.aid)) {
      this.#log.warn("ignoring end role: not a backer for the controller", { cid });
      return;
    }

    const verdict = RoutedEvent.verifyReply(message, state);
    if (!verdict.ok) {
      this.#log.warn("ignoring end role: reply verification failed", { cid, error: verdict.error });
      return;
    }

    const existing = await this.#storage.getRole(cid, "mailbox", this.aid);
    if (existing !== null && existing.body.dt >= message.body.dt) {
      this.#log.debug("ignoring end role: not newer than the stored one", { cid });
      return;
    }

    this.#log.debug("storing mailbox role", { cid });
    await this.#storage.putRole(message);
  }

  /** Stores the inner message of an `exn /fwd` under the recipient and topic it names. */
  async #storeForward(message: Message<ExchangeEventBody>): Promise<void> {
    const { q } = message.body;
    const pre = q.pre as string | undefined;
    const topic = q.topic as string | undefined;

    if (!pre || !topic) {
      this.#log.warn("ignoring forward: missing q.pre or q.topic");
      return;
    }

    // Open to the controllers this witness already witnesses and to nobody else:
    // otherwise `POST /` is an unauthenticated write into shared storage, which
    // is a spam relay and a storage DoS.
    if (!(await this.#keyState(pre))?.backers.includes(this.aid)) {
      this.#log.warn("ignoring forward: not a backer for the recipient", { pre, topic });
      return;
    }

    if (!MAILBOX_TOPICS.has(normalizeTopic(topic))) {
      this.#log.warn("ignoring forward: unknown topic", { pre, topic });
      return;
    }

    const innerMessage = RoutedEvent.embeds(message).evt;
    if (!innerMessage) {
      this.#log.warn("ignoring forward: missing e.evt", { pre, topic });
      return;
    }

    this.#log.debug("saving mailbox entry", { pre, topic });
    await this.#storage.saveMailboxEntry(pre, topic, innerMessage);
  }

  /**
   * Answers a `qry mbx`: entries per queried topic from the given inclusive
   * offset. The signature is verified against the KEL of the AID whose mailbox
   * the query names — the prefix on the signature group is a claim, so trusting
   * it leaves every mailbox on the host readable by anyone willing to rewrite
   * that one field, and these carry IPEX credential delivery.
   */
  async #queryMailbox(message: Message<QueryEventBody>): Promise<MailboxReply[]> {
    const { i, topics } = message.body.q as {
      i?: string;
      topics?: Record<string, number>;
    };

    if (!i || !topics) {
      this.#log.warn("ignoring query: missing q.i or q.topics");
      return [];
    }

    const state = await this.#keyState(i);
    if (!state?.backers.includes(this.aid)) {
      this.#log.warn("ignoring query: not a backer for the mailbox owner", { aid: i });
      return [];
    }

    // A `qry` carries the same signature shape as a `rpy` — a transferable group
    // naming the signer — and keri's verifier is generic across the two, but is
    // only exposed under the `rpy` name.
    const verdict = RoutedEvent.verifyReply(message as unknown as Message<ReplyEventBody>, state);
    if (!verdict.ok) {
      this.#log.warn("ignoring query: not signed by the mailbox owner", { aid: i, error: verdict.error });
      return [];
    }

    this.#log.debug("querying mailbox", { aid: i, topics });

    // Each topic is its own key range, so the scans are independent — and a poll
    // routinely names every topic KERIpy subscribes to, which is nine.
    const perTopic = await Promise.all(
      Object.entries(topics).map(async ([topic, offset]) =>
        (await Array.fromAsync(this.#storage.getMailboxEntries(i, topic, offset))).map((entry) => ({
          id: entry.id,
          topic,
          message: entry.message,
        })),
      ),
    );

    return perTopic.flat();
  }

  /**
   * Everything this witness has stored is partially witnessed by construction:
   * it saves an event the moment it receipts it, long before the other backers
   * have. Replaying without that allowance throws before anything else runs.
   */
  async #loadKel(pre: string): Promise<KeyEventLog> {
    // Materialized because `KeyEventLog.from` takes a sync iterable.
    const events = await Array.fromAsync(this.#storage.getKeyEvents(pre));
    return KeyEventLog.from(events, { allowPartiallyWitnessed: true });
  }

  /**
   * Memoized: `POST /` carries a batch, and every message in it is authorized
   * against this, so without a cache one request replays the same KEL — and
   * re-verifies every signature in it — once per message.
   *
   * Key state only, never the log itself: `#handleReceipt` merges into the
   * attachments it reads back, and a cached log would hand it a copy that
   * predates the last write.
   */
  #keyState(pre: string): Promise<KeyState | null> {
    const cached = this.#states.get(pre);
    if (cached !== undefined) {
      return cached;
    }

    const load = this.#loadKel(pre).then(
      (kel) => (kel.events.length === 0 ? null : kel.state),
      () => null,
    );

    // Bounded because a witness backs an unbounded number of controllers.
    // Evicting costs a replay, never correctness.
    if (this.#states.size >= KEY_STATE_CACHE) {
      const oldest = this.#states.keys().next();
      if (!oldest.done) {
        this.#states.delete(oldest.value);
      }
    }
    this.#states.set(pre, load);
    return load;
  }

  /** A stored event can change the state later reads are authorized against, so every write ends here. */
  #invalidate(aid: string): void {
    this.#states.delete(aid);
  }

  async #save(message: Message<KeyEventBody>): Promise<void> {
    await this.#storage.saveEvent(message, new Date());
    this.#invalidate(message.body.i);
  }

  async *getKeyEvents(aid: string): AsyncGenerator<Message<KeyEventBody>> {
    yield* this.#storage.getKeyEvents(aid);
  }

  /**
   * The `/end/role/add` naming this witness as `cid`'s mailbox. Served in the
   * controller's OOBI: it is how a sender learns to deposit here rather than
   * trying to reach the controller directly.
   */
  mailboxRole(cid: string): Promise<Message<ReplyEventBody> | null> {
    return this.#storage.getRole(cid, "mailbox", this.aid);
  }

  /** This witness's own `/loc/scheme`, which a peer needs to dial the mailbox it just learned about. */
  get location(): Message[] {
    return this.events
      .map((event) => event.message)
      .filter((message) => (message.body as { r?: string }).r === "/loc/scheme");
  }
}
