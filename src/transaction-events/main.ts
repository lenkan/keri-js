/**
 * Transaction events — the messages that make up a credential registry's
 * Transaction Event Log.
 *
 * Re-exported from the package root as the `TransactionEvent` namespace. `incept`
 * here is the registry inception (`vcp`), not the KEL's.
 */
export type {
  CredentialStatus,
  IssueEventArgs,
  IssueEventBody,
  RegistryInceptEventArgs,
  RegistryInceptEventBody,
  RevokeEventArgs,
  RevokeEventBody,
  TransactionEventBody,
} from "../core/main.ts";
export { inceptRegistry as incept, issue, isTransactionEvent, revoke } from "../core/main.ts";
