import type { KeyEventBody, Message, ReplyEventBody } from "keri";

export interface KeyEventStorage {
  saveMessage(message: Message): void;
  getKeyEvents(prefix: string): Generator<Message<KeyEventBody>>;
  getReplies(filter?: { route?: string; eid?: string; cid?: string }): Generator<Message<ReplyEventBody>>;
}
