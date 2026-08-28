/**
 * Authentic Chained Data Containers.
 *
 * Re-exported from the package root as the `Credential` namespace. An ACDC is not
 * a `t`-typed KERI event — it is a separate protocol, which is why
 * {@link isCredential} dispatches on the version string rather than a type field.
 *
 * Submodules needing more than this list import `./internal.ts`.
 */
export type {
  CredentialArgs,
  CredentialBody,
  CredentialEdges,
  CredentialRules,
  CredentialSaidResult,
  CredentialSubject,
} from "./credential.ts";
export { createCredential as create, disclosedAttributes, isCredential } from "./credential.ts";
