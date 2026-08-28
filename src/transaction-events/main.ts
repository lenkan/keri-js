/**
 * Transaction events — the messages that make up a credential registry's
 * Transaction Event Log.
 *
 * Re-exported from the package root as the `TransactionEvent` namespace. `incept`
 * here is the registry inception (`vcp`), not the KEL's. Submodules needing more
 * than this list import `./internal.ts`.
 */
export type { IssueEventArgs, IssueEventBody, RevokeEventArgs, RevokeEventBody } from "./credential-event.ts";
export { issue, revoke } from "./credential-event.ts";
export type { CredentialStatus, TransactionEventBody } from "./log.ts";
export { isTransactionEvent } from "./log.ts";
export type { RegistryInceptEventArgs, RegistryInceptEventBody } from "./registry-event.ts";
export { incept } from "./registry-event.ts";
