import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, Message, type MessageBody } from "#keri/cesr";
import type { ExchangeEventBody, QueryEventBody } from "#keri/core";
import { KeyEventLog, keri } from "#keri/core";
import type { MailboxServerStorage } from "#keri/storage";
import { type Logger, noopLogger } from "./logger.ts";

export interface MailboxOptions {
  storage: MailboxServerStorage;
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

export class Mailbox {
  readonly #storage: MailboxServerStorage;
  readonly #privateKey: Uint8Array;
  readonly #kel: KeyEventLog;
  readonly #log: Logger;
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
    this.#log = options.logger ?? noopLogger;

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

  async *handleMessage(message: Message): AsyncGenerator<MailboxReply> {
    const { t, r } = message.body as { t?: string; r?: string };

    if (t === "exn" && r === "/fwd") {
      this.#log.debug("handling exn /fwd");
      this.#handleForward(message as Message<ExchangeEventBody>);
      return;
    }

    if (t === "qry" && r === "mbx") {
      this.#log.debug("handling qry mbx");
      yield* this.#handleQuery(message as Message<QueryEventBody>);
      return;
    }

    this.#log.debug("ignoring message", { t, r });
  }

  #handleForward(message: Message<ExchangeEventBody>): void {
    const { q, e } = message.body;
    const pre = q.pre as string | undefined;
    const topic = q.topic as string | undefined;

    if (!pre || !topic) {
      this.#log.warn("ignoring forward: missing q.pre or q.topic");
      return;
    }

    const evtBody = e?.evt as MessageBody | undefined;
    if (!evtBody) {
      this.#log.warn("ignoring forward: missing e.evt", { pre, topic });
      return;
    }

    const evtCouple = message.attachments.PathedMaterialCouples.find((c) => c.path === "-e-evt");
    const innerMessage = new Message(evtBody, evtCouple?.attachments);

    this.#log.debug("saving mailbox entry", { pre, topic });
    this.#storage.saveMailboxEntry(pre, topic, innerMessage);
  }

  *#handleQuery(message: Message<QueryEventBody>): Generator<MailboxReply> {
    const { i, topics } = message.body.q as {
      i?: string;
      topics?: Record<string, number>;
    };

    if (!i || !topics) {
      this.#log.warn("ignoring query: missing q.i or q.topics");
      return;
    }

    this.#log.debug("querying mailbox", { aid: i, topics });
    for (const [topicPath, offset] of Object.entries(topics)) {
      const storageTopic = topicPath.replace(/^\//, "");
      for (const entry of this.#storage.getMailboxEntries(i, storageTopic, offset)) {
        yield { id: entry.id, topic: topicPath, message: entry.message };
      }
    }
  }

  #sign(message: Message): string {
    const rawSignature = ed25519.sign(message.raw, this.#privateKey);
    return encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: rawSignature }));
  }
}
