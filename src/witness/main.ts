/**
 * A KERI witness: receipts key events, holds mailboxes, and serves OOBIs.
 *
 * Unlike the rest of the package this one has a shape — it hands back a
 * `fetch(request)` and reads and writes through a `Store` you supply. It still
 * does no I/O of its own: the request comes from your runtime and the storage
 * is yours, so the same `Witness` runs on Workers, Deno, Node and Lambda.
 */

export type { Logger } from "./logger.ts";
export { MemoryStore } from "./memory-store.ts";
export type { Entry, ScanOptions, Store } from "./store.ts";
export { type MailboxReply, Witness, type WitnessEvent, type WitnessOptions } from "./witness.ts";
export { WitnessError } from "./witness-error.ts";
