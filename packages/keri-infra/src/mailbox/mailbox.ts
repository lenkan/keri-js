import { ed25519 } from "@noble/curves/ed25519.js";
import type { Message } from "cesr";
import type { ExchangeEventBody, QueryEventBody } from "keri";
import { ed25519Signer, KeyEvent, KeyEventLog, RoutedEvent, type Signer, signEvent } from "keri";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { MailboxServerStorage } from "../storage/main.ts";

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
  readonly #kel: KeyEventLog;
  readonly #log: KeriLogger;
  readonly events: readonly MailboxEvent[];

  static async createKEL(signer: Signer): Promise<KeyEventLog> {
    const icp = KeyEvent.incept({ signingKeys: [signer.publicKey], nextKeyDigests: [] });
    await signEvent(icp, [signer]);
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

      location.attachments = {
        NonTransReceiptCouples: [{ prefix: aid, sig: await signer.sign(location.raw) }],
      };

      endrole.attachments = {
        NonTransReceiptCouples: [{ prefix: aid, sig: await signer.sign(endrole.raw) }],
      };

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
    const { q } = message.body;
    const pre = q.pre as string | undefined;
    const topic = q.topic as string | undefined;

    if (!pre || !topic) {
      this.#log.warn("ignoring forward: missing q.pre or q.topic");
      return;
    }

    const innerMessage = RoutedEvent.embeds(message).evt;
    if (!innerMessage) {
      this.#log.warn("ignoring forward: missing e.evt", { pre, topic });
      return;
    }

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
}
