import { ed25519 } from "@noble/curves/ed25519.js";
import { Attachments, encodeText, Indexer, Matter, Message } from "cesr";
import {
  ed25519Signer,
  KeyEvent,
  type KeyEventBody,
  KeyEventLog,
  type ReceiptEventBody,
  RoutedEvent,
  type Signer,
  signEvent,
} from "keri";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { KeyEventStorage } from "../storage/main.ts";

export interface WitnessOptions {
  privateKey?: Uint8Array;
  url?: string;
  storage: KeyEventStorage;
  logger?: Logger;
}

export interface WitnessEvent {
  readonly message: Message;
  readonly timestamp: Date;
}

export class WitnessError extends Error {}

export class Witness {
  readonly events: readonly WitnessEvent[];

  readonly #storage: KeyEventStorage;
  readonly #signer: Signer;
  readonly #kel: KeyEventLog;
  readonly #log: KeriLogger;

  get aid() {
    return this.#kel.state.identifier;
  }

  static async createKEL(signer: Signer): Promise<KeyEventLog> {
    const icp = KeyEvent.incept({ signingKeys: [signer.publicKey], nextKeyDigests: [] });
    await signEvent(icp, [signer]);
    return KeyEventLog.from([icp]);
  }

  static async create(options: WitnessOptions): Promise<Witness> {
    const signer = ed25519Signer(options.privateKey ?? ed25519.utils.randomSecretKey(), { nonTransferable: true });
    const kel = await Witness.createKEL(signer);
    const aid = kel.state.identifier;

    const events: WitnessEvent[] = [{ message: kel.events[0], timestamp: new Date() }];

    if (options.url) {
      const url = new URL(options.url);
      const scheme = url.protocol.replace(":", "");

      const location = RoutedEvent.reply({
        r: "/loc/scheme",
        a: {
          eid: aid,
          scheme: scheme,
          url: options.url,
        },
      });

      const endrole = RoutedEvent.reply({
        r: "/end/role/add",
        a: {
          cid: aid,
          role: "controller",
          eid: aid,
        },
      });

      location.attachments = {
        NonTransReceiptCouples: [{ prefix: aid, sig: await signer.sign(location.raw) }],
      };

      endrole.attachments = {
        NonTransReceiptCouples: [{ prefix: aid, sig: await signer.sign(endrole.raw) }],
      };

      events.push({ message: location, timestamp: new Date() });
      events.push({ message: endrole, timestamp: new Date() });
    }

    return new Witness(options, signer, kel, events);
  }

  private constructor(options: WitnessOptions, signer: Signer, kel: KeyEventLog, events: WitnessEvent[]) {
    this.#storage = options.storage;
    this.#signer = signer;
    this.#kel = kel;
    this.#log = new KeriLogger(options.logger);
    this.events = events;
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

    let kel = KeyEventLog.from(this.#storage.getKeyEvents(body.i));

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

    const sig = await this.#signer.sign(message.raw);
    const receipt = KeyEvent.receipt(message);
    receipt.attachments = {
      NonTransReceiptCouples: [{ prefix: this.#kel.state.identifier, sig }],
    };

    const WitnessIdxSigs = [encodeText(Indexer.convert(Matter.parse(sig), witnessIndex))];

    const storedMessage = new Message(message.body, {
      ControllerIdxSigs: message.attachments.ControllerIdxSigs,
      WitnessIdxSigs,
      FirstSeenReplayCouples: [{ fnu: body.s, dt: new Date() }],
    });

    this.#storage.saveMessage(storedMessage);

    return receipt;
  }

  handleMessage(message: Message): void {
    const body = message.body as KeyEventBody;

    if (body.t !== "rct") {
      this.#log.debug("ignoring message: only rct handled", { t: body.t });
      return;
    }

    if (typeof body.i !== "string" || typeof body.d !== "string") {
      this.#log.warn("ignoring receipt: missing i/d");
      return;
    }

    const kel = KeyEventLog.from(this.#storage.getKeyEvents(body.i), {
      // TODO: This should only be for the event that is this receit
      allowPartiallyWitnessed: true,
    });

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

    const existingWigsByIndex = new Map<number, string>();
    for (const sig of storedEvent.attachments.WitnessIdxSigs) {
      const indexer = Indexer.parse(sig);
      existingWigsByIndex.set(indexer.index, sig);
    }

    for (const couple of message.attachments.NonTransReceiptCouples) {
      const witnessIndex = kel.state.backers.indexOf(couple.prefix);
      if (witnessIndex === -1) {
        continue;
      }
      const wigSig = encodeText(Indexer.convert(Matter.parse(couple.sig), witnessIndex));
      existingWigsByIndex.set(witnessIndex, wigSig);
    }

    const mergedAttachments = new Attachments({
      ControllerIdxSigs: storedEvent.attachments.ControllerIdxSigs,
      WitnessIdxSigs: Array.from(existingWigsByIndex.values()),
      FirstSeenReplayCouples: storedEvent.attachments.FirstSeenReplayCouples,
    });

    this.#log.debug("merged witness sigs", { aid: body.i, d: body.d, count: existingWigsByIndex.size });
    this.#storage.saveMessage(new Message(storedEvent.body, mergedAttachments));
  }

  *getKeyEvents(aid: string): Generator<Message<KeyEventBody>> {
    yield* this.#storage.getKeyEvents(aid);
  }
}
