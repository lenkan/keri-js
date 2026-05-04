import { ed25519 } from "@noble/curves/ed25519.js";
import { Attachments, encodeText, Indexer, Matter, Message } from "#keri/cesr";
import { type KeyEvent, type KeyEventBody, KeyEventLog, keri, type ReceiptEventBody } from "#keri/core";
import type { Logger } from "#keri/logging";
import type { KeyEventStorage } from "#keri/storage";

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
  readonly #privateKey: Uint8Array;
  readonly #kel: KeyEventLog;
  readonly #log: Logger | undefined;

  get aid() {
    return this.#kel.state.identifier;
  }

  static createKEL(privateKey: Uint8Array): KeyEventLog {
    const publicKey = encodeText(new Matter({ code: Matter.Code.Ed25519N, raw: ed25519.getPublicKey(privateKey) }));

    const icp = keri.incept({
      signingKeys: [publicKey],
      nextKeys: [],
    });
    icp.attachments = {
      ControllerIdxSigs: [encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey), 0))],
    };

    return KeyEventLog.from([icp]);
  }

  constructor(options: WitnessOptions) {
    this.#storage = options.storage;
    this.#privateKey = options.privateKey ?? ed25519.utils.randomSecretKey();
    this.#kel = Witness.createKEL(this.#privateKey);
    this.#log = options.logger;

    const events: WitnessEvent[] = [{ message: this.#kel.events[0], timestamp: new Date() }];

    if (options.url) {
      const url = new URL(options.url);
      const scheme = url.protocol.replace(":", "");

      const location = keri.reply({
        r: "/loc/scheme",
        a: {
          eid: this.aid,
          scheme: scheme,
          url: options.url,
        },
      });

      const endrole = keri.reply({
        r: "/end/role/add",
        a: {
          cid: this.aid,
          role: "controller",
          eid: this.aid,
        },
      });

      location.attachments = {
        NonTransReceiptCouples: [{ prefix: this.#kel.state.identifier, sig: this.#sign(location) }],
      };

      endrole.attachments = {
        NonTransReceiptCouples: [{ prefix: this.#kel.state.identifier, sig: this.#sign(endrole) }],
      };

      events.push({ message: location, timestamp: new Date() });
      events.push({ message: endrole, timestamp: new Date() });
    }

    this.events = events;
  }

  receipt(message: Message<KeyEventBody>): Message<ReceiptEventBody> {
    const body = message.body;

    if (typeof body.i !== "string" || typeof body.d !== "string" || typeof body.s !== "string") {
      this.#log?.warn("rejecting receipt: missing required fields i/d/s");
      throw new WitnessError("Missing required fields i, d, s");
    }

    if (message.attachments.ControllerIdxSigs.length === 0) {
      this.#log?.warn("rejecting receipt: no controller signatures", { aid: body.i, s: body.s, d: body.d });
      throw new WitnessError("Missing controller signatures");
    }

    let kel = KeyEventLog.from(this.#storage.getKeyEvents(body.i));

    try {
      kel = kel.append(message, { allowPartiallyWitnessed: true });
    } catch (error) {
      if (error instanceof Error) {
        this.#log?.warn("rejecting receipt: KEL append failed", {
          aid: body.i,
          s: body.s,
          d: body.d,
          error: error.message,
        });
        throw new WitnessError(`Failed to append message to KEL: ${error.message}`);
      }
    }

    this.#log?.debug("issuing receipt", { aid: body.i, s: body.s, d: body.d });

    const sig = this.#sign(message);
    const witnessIndex = kel.state.backers.indexOf(this.aid);

    const receipt = keri.receipt({ d: message.body.d, i: message.body.i, s: message.body.s });
    receipt.attachments = {
      NonTransReceiptCouples: [{ prefix: this.#kel.state.identifier, sig }],
    };

    const WitnessIdxSigs = witnessIndex >= 0 ? [encodeText(Indexer.convert(Matter.parse(sig), witnessIndex))] : [];

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
      this.#log?.debug("ignoring message: only rct handled", { t: body.t });
      return;
    }

    if (typeof body.i !== "string" || typeof body.d !== "string") {
      this.#log?.warn("ignoring receipt: missing i/d");
      return;
    }

    const kel = KeyEventLog.from(this.#storage.getKeyEvents(body.i), {
      // TODO: This should only be for the event that is this receit
      allowPartiallyWitnessed: true,
    });

    if (!kel.state.backers.includes(this.aid)) {
      this.#log?.debug("ignoring receipt: not a backer", { aid: body.i, d: body.d });
      return;
    }

    const storedEvent = kel.events.find((event) => event.body.d === body.d);
    if (!storedEvent) {
      this.#log?.debug("ignoring receipt: no matching stored event", { aid: body.i, d: body.d });
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

    this.#log?.debug("merged witness sigs", { aid: body.i, d: body.d, count: existingWigsByIndex.size });
    this.#storage.saveMessage(new Message(storedEvent.body, mergedAttachments));
  }

  *getKeyEvents(aid: string): Generator<KeyEvent> {
    yield* this.#storage.getKeyEvents(aid);
  }

  #sign(message: Message): string {
    const rawSignature = ed25519.sign(message.raw, this.#privateKey);
    return encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: rawSignature }));
  }
}
