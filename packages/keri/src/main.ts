/**
 * The public surface.
 *
 * Message constructors are grouped by protocol into four namespaces. Each is an
 * ES module namespace, not a class — `KeyEvent.incept(...)` returns a `Message`,
 * so a class would promise an instance type it can never produce. Every member
 * is also importable one at a time from the matching subpath:
 *
 *     import { KeyEvent } from "keri";
 *     import { incept } from "keri/key-events";   // the same function
 */

export {
  Attachments,
  type AttachmentsInit,
  Counter,
  type FirstSeenReplayCouple,
  type Frame,
  Indexer,
  Matter,
  Message,
  type MessageBody,
  type NonTransReceiptCouple,
  type ParseInput,
  type PathedMaterialCouple,
  parse,
  type SealSourceCouple,
  type SealSourceTriple,
  type TransIdxSigGroup,
  type TransLastIdxSigGroup,
  VersionString,
} from "cesr";
export type {
  AppendOptions,
  CheckStatus,
  CredentialArgs,
  CredentialBody,
  CredentialCheck,
  CredentialCheckId,
  CredentialEdge,
  CredentialEdges,
  CredentialRules,
  CredentialSaidResult,
  CredentialStatus,
  CredentialSubject,
  CredentialVerification,
  DelegatedInceptArgs,
  DelegatedRotateArgs,
  DipEventBody,
  DrtEventBody,
  Ed25519SignerOptions,
  ExchangeEventArgs,
  ExchangeEventBody,
  GenerateKeyPairOptions,
  IdentifierVerification,
  InceptArgs,
  InceptEventBody,
  InteractArgs,
  InteractEventBody,
  IssueEventArgs,
  IssueEventBody,
  KeyEventBody,
  KeyPair,
  KeyState,
  QueryEventArgs,
  QueryEventBody,
  ReceiptEventBody,
  RegistryInceptEventArgs,
  RegistryInceptEventBody,
  RegistryVerification,
  ReplyEventArgs,
  ReplyEventBody,
  RevokeEventArgs,
  RevokeEventBody,
  RotateArgs,
  RotateEventBody,
  RoutedEventBody,
  Signer,
  Threshold,
  TransactionEventBody,
  VerifyReport,
  VerifyResult,
} from "./core/main.ts";
export {
  collect,
  EventIndex,
  ed25519Signer,
  // Public because an ACDC's attribute-section `dt` is caller data, not a
  // constructor argument — the event constructors all take a `Date`.
  formatDate,
  generateKeyPair,
  KeyEventLog,
  nextKeyDigest,
  saidify,
  signEvent,
  verify,
  verifySignature,
} from "./core/main.ts";
export * as Credential from "./credentials/main.ts";
export * as KeyEvent from "./key-events/main.ts";
export * as RoutedEvent from "./routed-events/main.ts";
export * as TransactionEvent from "./transaction-events/main.ts";
