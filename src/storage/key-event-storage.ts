import type { KeyEvent, Message, ReplyEventBody } from "#keri/core";

export interface KeyEventStorage {
  saveMessage(message: Message): void;
  getKeyEvents(prefix: string): Generator<KeyEvent>;
  getReplies(filter?: { route?: string; eid?: string; cid?: string }): Generator<Message<ReplyEventBody>>;
}
