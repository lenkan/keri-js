/**
 * The cross-protocol pass: index a settled stream, then check every identifier,
 * registry and credential in it against each other.
 *
 * The only submodule allowed to see all four protocols at once. Parsing is
 * streaming and syntax-only, so collecting and verifying are separate steps.
 */
export type {
  CheckStatus,
  CredentialCheck,
  CredentialCheckId,
  CredentialEdge,
  CredentialVerification,
} from "./credential-verification.ts";
export { verifyCredential, verifyCredentials } from "./credential-verification.ts";
export { EventIndex } from "./event-index.ts";
export type { IdentifierVerification, RegistryVerification, VerifyReport } from "./report.ts";
export { collect, verify } from "./report.ts";
