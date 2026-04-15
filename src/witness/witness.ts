import { ed25519 } from "@noble/curves/ed25519.js";
import { Indexer, Matter, Message } from "../cesr/__main__.ts";
import { type KeyEvent, type KeyEventBody, KeyEventLog, keri, type ReceiptEventBody } from "../core/main.ts";
import type { KeyEventStorage } from "../storage/key-event-storage.ts";

export interface WitnessOptions {
  privateKey?: Uint8Array;
  url?: string;
  storage: KeyEventStorage;
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

  get aid() {
    return this.#kel.state.identifier;
  }

  static createKEL(options: WitnessOptions): KeyEventLog {
    const privateKey = options.privateKey ?? ed25519.utils.randomSecretKey();
    const publicKey = new Matter({ code: Matter.Code.Ed25519N, raw: ed25519.getPublicKey(privateKey) }).text();

    const icp = keri.incept({
      signingKeys: [publicKey],
      nextKeys: [],
    });
    icp.attachments = {
      ControllerIdxSigs: [Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey), 0).text()],
    };

    return KeyEventLog.from([icp]);
  }

  constructor(options: WitnessOptions) {
    this.#storage = options.storage;
    this.#privateKey = options.privateKey ?? ed25519.utils.randomSecretKey();
    this.#kel = Witness.createKEL(options);

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
      throw new WitnessError("Missing required fields i, d, s");
    }

    if (message.attachments.ControllerIdxSigs.length === 0) {
      throw new WitnessError("Missing controller signatures");
    }

    const receipt = keri.receipt({ d: message.body.d, i: message.body.i, s: message.body.s });
    receipt.attachments = {
      NonTransReceiptCouples: [{ prefix: this.#kel.state.identifier, sig: this.#sign(message) }],
    };

    const storedMessage = new Message(message.body, {
      ControllerIdxSigs: message.attachments.ControllerIdxSigs,
      NonTransReceiptCouples: [
        ...message.attachments.NonTransReceiptCouples,
        ...receipt.attachments.NonTransReceiptCouples,
      ],
      FirstSeenReplayCouples: [{ fnu: body.s, dt: new Date() }],
    });

    this.#storage.saveMessage(storedMessage);

    return receipt;
  }

  *getKeyEvents(aid: string): Generator<KeyEvent> {
    yield* this.#storage.getKeyEvents(aid);
  }

  #sign(message: Message): string {
    const rawSignature = ed25519.sign(message.raw, this.#privateKey);
    return new Matter({ code: Matter.Code.Ed25519_Sig, raw: rawSignature }).text();
  }
}
