/**
 * Registry events — the `vcp`/`iss`/`rev` messages that make up a credential
 * registry's Transaction Event Log.
 *
 * Re-exported from the package root as the `Registry` namespace. `incept` here
 * is the registry inception (`vcp`), not the KEL's. Submodules needing more than
 * this list import `./internal.ts`.
 */
export type { IssueEventArgs, IssueEventBody, RevokeEventArgs, RevokeEventBody } from "./credential-event.ts";
export { issue, revoke } from "./credential-event.ts";
export type { CredentialStatus, RegistryEventBody } from "./log.ts";
export { isRegistryEvent } from "./log.ts";
export type { RegistryInceptEventArgs, RegistryInceptEventBody } from "./registry-event.ts";
export { incept } from "./registry-event.ts";
