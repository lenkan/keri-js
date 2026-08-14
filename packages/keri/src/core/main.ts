import { createCredential } from "./credential.ts";
import { issue, revoke } from "./credential-event.ts";
import { digest } from "./digest.ts";
import { formatDate } from "./events.ts";
import { delegatedIncept, delegatedRotate, incept, interact, rotate } from "./key-event.ts";
import { generateKeyPair } from "./keys.ts";
import { receipt } from "./receipt-event.ts";
import { incept as registry } from "./registry-event.ts";
import { exchange, query, reply } from "./routed-event.ts";
import { sign } from "./sign.ts";
import { verifyThreshold } from "./verify.ts";

export {
  Attachments,
  type AttachmentsInit,
  type FirstSeenReplayCouple,
  type Frame,
  Message,
  type MessageBody,
  type NonTransReceiptCouple,
  type PathedMaterialCouple,
  type SealSourceCouple,
  type SealSourceTriple,
  type TransIdxSigGroup,
  type TransLastIdxSigGroup,
  VersionString,
} from "cesr";
export type {
  Credential,
  CredentialBody,
  CredentialBodyInit,
  CredentialEdges,
  CredentialRules,
  CredentialSaidResult,
  CredentialSubject,
} from "./credential.ts";
export { createCredential, credentialIssuee, disclosedAttributes, verifyCredentialSaid } from "./credential.ts";
export type {
  IssueEventBody as IssueEvent,
  IssueEventInit,
  RevokeEventBody as RevokeEvent,
  RevokeEventInit,
} from "./credential-event.ts";
export type {
  CheckStatus,
  CredentialCheck,
  CredentialCheckId,
  CredentialEdge,
  CredentialVerification,
} from "./credential-verification.ts";
export { verifyCredential, verifyCredentials } from "./credential-verification.ts";
export type { Endpoint, EndRoleRecord, LocationRecord } from "./endpoint-discovery.ts";
export { resolveEndRole, resolveLocation } from "./endpoint-discovery.ts";
export { EventIndex } from "./event-index.ts";
export type { WitnessEndpoint } from "./kawa.ts";
export { submitToWitnesses } from "./kawa.ts";
export type {
  DelegatedInceptArgs,
  DelegatedRotateArgs,
  DipEventBody,
  DrtEventBody,
  InceptArgs,
  InceptEventBody,
  InteractArgs,
  InteractEventBody,
  KeyEvent,
  KeyEventBody,
  KeyState,
  RotateArgs,
  RotateEventBody,
} from "./key-event.ts";
export { delegatedIncept, delegatedRotate } from "./key-event.ts";
export { isKelEventType, KeyEventLog } from "./key-event-log.ts";
export type { GenerateKeyPairOptions, KeyPair } from "./keys.ts";
export { generateKeyPair } from "./keys.ts";

export type { MailboxClientOptions } from "./mailbox-client.ts";
export { MailboxClient } from "./mailbox-client.ts";
export type { ReceiptEventBody, ReceiptEventInit } from "./receipt-event.ts";
export type { RegistryInceptEventBody, RegistryInceptEventInit } from "./registry-event.ts";
export type {
  ExchangeEventBody,
  ExchangeEventInit,
  QueryEventBody,
  QueryEventInit,
  ReplyEventBody,
  ReplyEventInit,
} from "./routed-event.ts";
export type { SignOptions } from "./sign.ts";
export { sign } from "./sign.ts";
export type { Threshold } from "./threshold.ts";
export type { CredentialStatus, TransactionEventBody } from "./transaction-event-log.ts";
export { isTelEventType, verifyTransactionEventAnchor, verifyTransactionEventSaid } from "./transaction-event-log.ts";
export type { VerifyOptions, VerifyResult } from "./verify.ts";
export { verifySignature } from "./verify.ts";

export const keri = {
  // Key events
  incept,
  interact,
  rotate,
  delegatedIncept,
  delegatedRotate,
  // Registry
  registry,
  issue,
  revoke,
  credential: createCredential,
  // Routed
  exchange,
  query,
  reply,
  // Receipt
  receipt,
  utils: {
    sign,
    verifyThreshold,
    formatDate,
    generateKeyPair,
    digest,
  },
};
