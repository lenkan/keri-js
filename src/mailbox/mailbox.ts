import { Message, type MessageBody } from "#keri/cesr";
import type { ExchangeEventBody, QueryEventBody } from "#keri/core";
import type { MailboxServerStorage } from "#keri/storage";

export interface MailboxOptions {
  storage: MailboxServerStorage;
}

export class Mailbox {
  readonly #storage: MailboxServerStorage;

  constructor(options: MailboxOptions) {
    this.#storage = options.storage;
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
}
