/**
 * Aggregation point for the `core` submodule.
 *
 * Not the package's public surface — `src/main.ts` is, and it names what it
 * exports explicitly. Anything listed here is reachable by the other submodules;
 * only what `src/main.ts` re-exports reaches consumers.
 */
export type {
  Attachments,
  AttachmentsInit,
  FirstSeenReplayCouple,
  Frame,
  MessageBody,
  NonTransReceiptCouple,
  ParseInput,
  PathedMaterialCouple,
  SealSourceCouple,
  SealSourceTriple,
  TransIdxSigGroup,
  TransLastIdxSigGroup,
} from "cesr";
export type {
  CredentialArgs,
  CredentialBody,
  CredentialEdges,
  CredentialRules,
  CredentialSaidResult,
  CredentialSubject,
} from "./credential.ts";
export { createCredential, disclosedAttributes, isCredential } from "./credential.ts";
export type { IssueEventArgs, IssueEventBody, RevokeEventArgs, RevokeEventBody } from "./credential-event.ts";
export { issue, revoke } from "./credential-event.ts";
export type {
  CheckStatus,
  CredentialCheck,
  CredentialCheckId,
  CredentialEdge,
  CredentialVerification,
} from "./credential-verification.ts";
export { nextKeyDigest } from "./digest.ts";
export { EventIndex } from "./event-index.ts";
export { formatDate } from "./events.ts";
export type { ExchangeVerification, ExchangeVerificationFailure } from "./exchange-verification.ts";
export { verifyExchange, verifyReply } from "./exchange-verification.ts";
export type {
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
  RotateArgs,
  RotateEventBody,
} from "./key-event.ts";
export {
  delegatedIncept,
  delegatedRotate,
  incept,
  interact,
  isEstablishment,
  isKeyEvent,
  rotate,
} from "./key-event.ts";
export { type AppendOptions, KeyEventLog } from "./key-event-log.ts";
export type { GenerateKeyPairOptions, KeyPair } from "./keys.ts";
export { generateKeyPair } from "./keys.ts";
export type { ReceiptEventBody } from "./receipt-event.ts";
export { receipt } from "./receipt-event.ts";
export type { RegistryInceptEventArgs, RegistryInceptEventBody } from "./registry-event.ts";
// Aliased because the package exposes two inceptions — this one is the registry's
// `vcp`. At the root they are told apart by namespace, not by name.
export { incept as inceptRegistry } from "./registry-event.ts";
export type {
  ExchangeEventArgs,
  ExchangeEventBody,
  QueryEventArgs,
  QueryEventBody,
  ReplyEventArgs,
  ReplyEventBody,
  RoutedEventBody,
} from "./routed-event.ts";
export {
  CHALLENGE_RESPONSE_ROUTE,
  embeds,
  exchange,
  IPEX_GRANT_ROUTE,
  isRoutedEvent,
  query,
  reply,
} from "./routed-event.ts";
export { saidify } from "./said.ts";
export type { Ed25519SignerOptions, EndorseOptions, Signature, SignEventOptions, Signer } from "./sign.ts";
export { ed25519Signer, endorse, signEvent } from "./sign.ts";
export type { Threshold } from "./threshold.ts";
export type { CredentialStatus, TransactionEventBody } from "./transaction-event-log.ts";
export { isTransactionEvent } from "./transaction-event-log.ts";
export type { VerifyResult } from "./verify.ts";
export { verifySignature } from "./verify.ts";
export type { IdentifierVerification, RegistryVerification, VerifyReport } from "./verify-report.ts";
export { collect, verify } from "./verify-report.ts";
