import type { Message } from "#keri/cesr";

export interface MailboxEntry {
  id: number;
  message: Message;
}

export interface MailboxServerStorage {
  saveMailboxEntry(pre: string, topic: string, message: Message): void;
  getMailboxEntries(pre: string, topic: string, offset: number): Generator<MailboxEntry>;
}
