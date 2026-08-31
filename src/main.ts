/**
 * The public surface.
 *
 * Message constructors are grouped by protocol into four namespaces. Each is an
 * ES module namespace, not a class — `KeyEvent.incept(...)` returns a `Message`,
 * so a class would promise an instance type it can never produce.
 *
 * Namespaces are nouns — the messages. Everything at the top level is a verb or
 * the state a verb acts on, so a pipeline reads without a prefix:
 *
 *     KeyEventLog.empty().append(signEvent(KeyEvent.incept({ … }), { signers }))
 *
 * The byte layer — `Matter`, `Indexer`, `Counter`, `Attachments`, `parse` — is
 * `keri/cesr`. Only `Message` is repeated here, because every constructor
 * returns one.
 */

export { Message } from "./cesr/main.ts";
export type {
  CredentialArgs,
  CredentialBody,
  CredentialEdges,
  CredentialRules,
  CredentialSaidResult,
  CredentialSubject,
} from "./credentials/main.ts";
export * as Credential from "./credentials/main.ts";
// Public because an ACDC's attribute-section `dt` is caller data, not a
// constructor argument — the event constructors all take a `Date`.
export { formatDate, saidify } from "./events/main.ts";
export type {
  AppendOptions,
  DelegatedInceptArgs,
  DelegatedRotateArgs,
  DipEventBody,
  DrtEventBody,
  InceptArgs,
  InceptEventBody,
  InteractArgs,
  InteractEventBody,
  KeyEventBody,
  KeyState,
  ReceiptArgs,
  ReceiptEventBody,
  RotateArgs,
  RotateEventBody,
  SignEventOptions,
} from "./key-events/main.ts";
export * as KeyEvent from "./key-events/main.ts";
export { KeyEventLog, signEvent } from "./key-events/main.ts";
export type {
  Ed25519SignerOptions,
  GenerateKeyPairOptions,
  KeyPair,
  Signature,
  Signer,
  Threshold,
  VerifyResult,
} from "./keys/main.ts";
export { ed25519Signer, generateKeyPair, nextKeyDigest, verifySignature } from "./keys/main.ts";
export type {
  CredentialStatus,
  IssueEventArgs,
  IssueEventBody,
  RegistryEventBody,
  RegistryInceptEventArgs,
  RegistryInceptEventBody,
  RevokeEventArgs,
  RevokeEventBody,
} from "./registries/main.ts";
export * as Registry from "./registries/main.ts";
export type {
  EndorseOptions,
  ExchangeEventArgs,
  ExchangeEventBody,
  ExchangeVerification,
  ExchangeVerificationFailure,
  QueryEventArgs,
  QueryEventBody,
  ReplyEventArgs,
  ReplyEventBody,
  RoutedEventBody,
} from "./routed-events/main.ts";
export * as RoutedEvent from "./routed-events/main.ts";
export { endorse } from "./routed-events/main.ts";
export type {
  CheckStatus,
  CredentialCheck,
  CredentialCheckId,
  CredentialEdge,
  CredentialVerification,
  IdentifierVerification,
  RegistryVerification,
  VerifyReport,
} from "./verification/main.ts";
export { collect, EventIndex, verify } from "./verification/main.ts";
