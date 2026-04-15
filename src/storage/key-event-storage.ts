import type { KeyEvent, Message, ReplyEventBody } from "../core/main.ts";

export interface KeyEventStorage {
  saveMessage(message: Message): void;
  getKeyEvents(prefix: string): Generator<KeyEvent>;
  getReplies(filter?: { route?: string; eid?: string; cid?: string }): Generator<Message<ReplyEventBody>>;
}
