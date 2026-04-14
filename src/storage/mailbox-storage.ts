export interface MailboxStorage {
  getMailboxOffset(prefix: string, topic: string): number;
  saveMailboxOffset(prefix: string, topic: string, offset: number): void;
}
