import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, Message, type MessageBody } from "#keri/cesr";
import type { ExchangeEventBody, QueryEventBody } from "#keri/core";
import { KeyEventLog, keri } from "#keri/core";
import type { MailboxServerStorage } from "#keri/storage";

export interface MailboxOptions {
  storage: MailboxServerStorage;
  privateKey?: Uint8Array;
  url?: string;
}

export interface MailboxEvent {
  readonly message: Message;
  readonly timestamp: Date;
}

export class Mailbox {
  readonly #storage: MailboxServerStorage;
  readonly #privateKey: Uint8Array;
  readonly #kel: KeyEventLog;
  readonly events: readonly MailboxEvent[];

  static createKEL(privateKey: Uint8Array): KeyEventLog {
    const publicKey = encodeText(new Matter({ code: Matter.Code.Ed25519N, raw: ed25519.getPublicKey(privateKey) }));
    const icp = keri.incept({ signingKeys: [publicKey], nextKeys: [] });
    icp.attachments = {
      ControllerIdxSigs: [encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey), 0))],
    };
    return KeyEventLog.from([icp]);
  }

  get aid(): string {
    return this.#kel.state.identifier;
  }

  constructor(options: MailboxOptions) {
    this.#storage = options.storage;
    this.#privateKey = options.privateKey ?? ed25519.utils.randomSecretKey();
    this.#kel = Mailbox.createKEL(this.#privateKey);

    const events: MailboxEvent[] = [{ message: this.#kel.events[0], timestamp: new Date() }];

    if (options.url) {
      const url = new URL(options.url);
      const scheme = url.protocol.replace(":", "");

      const location = keri.reply({
        r: "/loc/scheme",
        a: { eid: this.aid, scheme, url: options.url },
      });

      const endrole = keri.reply({
        r: "/end/role/add",
        a: { cid: this.aid, role: "mailbox", eid: this.aid },
      });

      location.attachments = {
        NonTransReceiptCouples: [{ prefix: this.aid, sig: this.#sign(location) }],
      };

      endrole.attachments = {
        NonTransReceiptCouples: [{ prefix: this.aid, sig: this.#sign(endrole) }],
      };

      events.push({ message: location, timestamp: new Date() });
      events.push({ message: endrole, timestamp: new Date() });
    }

    this.events = events;
  }

  async *handleMessage(message: Message): AsyncGenerator<Message> {
    const { t, r } = message.body as { t?: string; r?: string };

    if (t === "exn" && r === "/fwd") {
      this.#handleForward(message as Message<ExchangeEventBody>);
      return;
    }

    if (t === "qry" && r === "mbx") {
      yield* this.#handleQuery(message as Message<QueryEventBody>);
    }
  }

  #handleForward(message: Message<ExchangeEventBody>): void {
    const { q, e } = message.body;
    const pre = q.pre as string | undefined;
    const topic = q.topic as string | undefined;

    if (!pre || !topic) {
      return;
    }

    const evtBody = e?.evt as MessageBody | undefined;
    if (!evtBody) {
      return;
    }

    const evtCouple = message.attachments.PathedMaterialCouples.find((c) => c.path === "-e-evt");
    const innerMessage = new Message(evtBody, evtCouple?.attachments);

    this.#storage.saveMailboxEntry(pre, topic, innerMessage);
  }

  *#handleQuery(message: Message<QueryEventBody>): Generator<Message> {
    const { i, topics } = message.body.q as {
      i?: string;
      topics?: Record<string, number>;
    };

    if (!i || !topics) {
      return;
    }

    for (const [topicPath, offset] of Object.entries(topics)) {
      const topic = topicPath.replace(/^\//, "");
      yield* this.#storage.getMailboxEntries(i, topic, offset);
    }
  }

  #sign(message: Message): string {
    const rawSignature = ed25519.sign(message.raw, this.#privateKey);
    return encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: rawSignature }));
  }
}
