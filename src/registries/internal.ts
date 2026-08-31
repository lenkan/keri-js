/**
 * What other submodules may reach for, beyond the public `Registry` namespace.
 * See `../key-events/internal.ts` for why this split exists.
 */

export {
  type CredentialTel,
  isTelEventType,
  type ResolveCredentialTelArgs,
  resolveCredentialTel,
  verifyRegistryEventAnchor,
  verifyRegistryEventSaid,
} from "./log.ts";
export * from "./main.ts";
