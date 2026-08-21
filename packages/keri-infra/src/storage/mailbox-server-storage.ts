import type { Message } from "cesr";

export interface MailboxEntry {
  /** Dense per-(pre, topic) ordinal starting at 0 — what KERIpy calls `fn` and the SSE `id:` field carries. */
  id: number;
  message: Message;
}

export interface MailboxServerStorage {
  saveMailboxEntry(pre: string, topic: string, message: Message): void;
  /** `offset` is the inclusive start ordinal: KERIpy polls with lastSeenId + 1. */
  getMailboxEntries(pre: string, topic: string, offset: number): Generator<MailboxEntry>;
}
