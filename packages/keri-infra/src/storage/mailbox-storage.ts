/** The client-side poll cursor: the next ordinal to fetch (inclusive), i.e. last seen id + 1. */
export interface MailboxStorage {
  getMailboxOffset(prefix: string, topic: string): number;
  saveMailboxOffset(prefix: string, topic: string, offset: number): void;
}
