import { ed25519 } from "@noble/curves/ed25519.js";
import { type Message, parse } from "cesr";
import { encodeUtf8 } from "cesr/encoding";
import type { ReplyEventBody } from "keri";
import { ed25519Signer, endorse, KeyEvent, KeyEventLog, RoutedEvent, type Signer, signEvent } from "keri";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { CredentialStorage, KeyEventStorage, MailboxServerStorage } from "../storage/main.ts";

export type PortalStorage = MailboxServerStorage & KeyEventStorage & CredentialStorage;

export interface PortalOptions {
  storage: PortalStorage;
  privateKey?: Uint8Array;
  url?: string;
  logger?: Logger;
}

export interface PortalEvent {
  readonly message: Message;
  readonly timestamp: Date;
}

export type EnrollResult = { ok: true; aid: string } | { ok: false; error: string };

async function* single(chunk: Uint8Array): AsyncIterable<Uint8Array> {
  yield chunk;
}

/**
 * The portal's identity: a non-transferable AID, its one-event KEL, and the
 * advertisement that tells senders where to reach it.
 *
 * It stores and forwards mail and publishes its enrolled users' KELs, but it
 * is neither a mailbox nor a witness — those are separate endpoints with their
 * own identities, and the portal only overlaps with them in what it does, not
 * in what it is.
 */
export class Portal {
  readonly events: readonly PortalEvent[];

  readonly #storage: PortalStorage;
  readonly #kel: KeyEventLog;
  readonly #log: KeriLogger;

  get aid(): string {
    return this.#kel.state.identifier;
  }

  static async create(options: PortalOptions): Promise<Portal> {
    const signer = ed25519Signer(options.privateKey ?? ed25519.utils.randomSecretKey(), { nonTransferable: true });
    const kel = await Portal.createKEL(signer);
    const aid = kel.state.identifier;

    const events: PortalEvent[] = [{ message: kel.events[0], timestamp: new Date() }];

    if (options.url) {
      // Advertised as a bare origin, because KERIpy composes request paths onto
      // whatever the location advertises (`kli mailbox add` appends /mailboxes,
      // sendDirect appends /). Requires keripy >= 1.3.6 — older kli composed a
      // bare origin into the scheme-relative "//mailboxes" and refused it.
      const base = options.url.replace(/\/+$/, "");
      const url = new URL(base);

      const location = RoutedEvent.reply({
        r: "/loc/scheme",
        a: { eid: aid, scheme: url.protocol.replace(":", ""), url: base },
      });

      // `controller`, and deliberately NOT `mailbox`: controller is what makes
      // KERIpy's Poster deliver grants and challenge responses straight here,
      // and advertising a mailbox role for the portal's own AID would make
      // Poster send every message twice, since it sends to ALL advertised
      // roles. Enrolled users still name this AID as their mailbox — that is
      // their reply to store, not the portal's claim about itself.
      const endrole = RoutedEvent.reply({
        r: "/end/role/add",
        a: { cid: aid, role: "controller", eid: aid },
      });

      endorse(location, { signers: [signer], state: kel.state });
      endorse(endrole, { signers: [signer], state: kel.state });

      events.push({ message: location, timestamp: new Date() });
      events.push({ message: endrole, timestamp: new Date() });
    }

    return new Portal(options, kel, events);
  }

  static async createKEL(signer: Signer): Promise<KeyEventLog> {
    const icp = KeyEvent.incept({ signingKeys: [signer.publicKey], nextKeyDigests: [] });
    signEvent(icp, { signers: [signer] });
    return KeyEventLog.from([icp]);
  }

  private constructor(options: PortalOptions, kel: KeyEventLog, events: PortalEvent[]) {
    this.#storage = options.storage;
    this.#kel = kel;
    this.#log = new KeriLogger(options.logger);
    this.events = events;
  }

  /**
   * The `kli mailbox add` contract: the controller POSTs its full KEL and a
   * signed `/end/role/add` naming this portal. Everything is verified before
   * anything is stored — the KEL replays, and the rpy must be signed by the
   * KEL's current keys, sealed to its last establishment event.
   */
  async enroll(kel: string, rpy: string): Promise<EnrollResult> {
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

    // `mailbox` is KERIpy's role name for "the endpoint holding my mail", which
    // is what kli writes and looks for. It says nothing about what this AID is.
    const { r, a } = reply.body;
    if (r !== "/end/role/add" || a.cid !== aid || a.role !== "mailbox" || a.eid !== this.aid) {
      return { ok: false, error: "The rpy must be /end/role/add naming the KEL's AID as cid and this portal as eid" };
    }

    const verdict = RoutedEvent.verifyReply(reply, kelLog.state);
    if (!verdict.ok) {
      return { ok: false, error: `Reply verification failed: ${verdict.error}` };
    }

    for (const event of kelLog.events) {
      this.#storage.saveMessage(event);
    }
    this.#storage.saveMessage(reply);

    this.#log.debug("enrolled", { aid });
    return { ok: true, aid };
  }

  /**
   * OOBI for an enrolled AID, in KERIpy's emit order: the KEL, this portal's
   * own `/loc/scheme`, then the stored `/end/role/add` naming this portal.
   * Null when the AID is unknown.
   *
   * This is how an enrolled user's KEL reaches anyone at all: neither side of
   * the demo runs a witness, so the portal is the only place either KEL is
   * published.
   */
  serveOobi(aid: string): Message[] | null {
    const kel = Array.from(this.#storage.getKeyEvents(aid));
    if (kel.length === 0) {
      return null;
    }

    const endRoles = Array.from(this.#storage.getReplies({ cid: aid, route: "/end/role/add" })).filter(
      (message) => message.body.a.role === "mailbox" && message.body.a.eid === this.aid,
    );

    const location = this.events
      .map((event) => event.message)
      .filter((message) => (message.body as { r?: string }).r === "/loc/scheme");

    return [...kel, ...(endRoles.length > 0 ? location : []), ...endRoles];
  }
}
