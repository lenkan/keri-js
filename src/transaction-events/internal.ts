/**
 * What other submodules may reach for, beyond the public `TransactionEvent`
 * namespace. See `../key-events/internal.ts` for why this split exists.
 */

export {
  type CredentialTel,
  isTelEventType,
  type ResolveCredentialTelArgs,
  resolveCredentialTel,
  verifyTransactionEventAnchor,
  verifyTransactionEventSaid,
} from "./log.ts";
export * from "./main.ts";
