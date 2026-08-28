/**
 * What other submodules may reach for, beyond the public `Credential` namespace.
 * See `../key-events/internal.ts` for why this split exists.
 */

export { credentialIssuee, verifyCredentialSaid } from "./credential.ts";
export * from "./main.ts";
