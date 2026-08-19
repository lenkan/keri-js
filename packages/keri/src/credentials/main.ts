/**
 * Authentic Chained Data Containers.
 *
 * Re-exported from the package root as the `Credential` namespace. An ACDC is not
 * a `t`-typed KERI event — it is a separate protocol, which is why
 * {@link isCredential} dispatches on the version string rather than a type field.
 */
export type {
  CredentialArgs,
  CredentialBody,
  CredentialEdges,
  CredentialRules,
  CredentialSaidResult,
  CredentialSubject,
} from "../core/main.ts";
export { createCredential as create, disclosedAttributes, isCredential } from "../core/main.ts";
