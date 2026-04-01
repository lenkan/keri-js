import { createCredential } from "./credential.ts";
import { issue, revoke } from "./credential-event.ts";
import { digest } from "./digest.ts";
import { formatDate } from "./events.ts";
import { incept, interact, rotate } from "./key-event.ts";
import { generateKeyPair } from "./keys.ts";
import { receipt } from "./receipt-event.ts";
import { incept as registry } from "./registry-event.ts";
import { exchange, query, reply } from "./routed-event.ts";
import { sign } from "./sign.ts";
import { verify } from "./verify.ts";

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
} from "../cesr/__main__.ts";
export type {
  Credential,
  CredentialBody,
  CredentialBodyInit,
  CredentialEdges,
  CredentialRules,
  CredentialSubject,
} from "./credential.ts";
export { createCredential } from "./credential.ts";
export type { IssueEvent, IssueEventInit, RevokeEvent, RevokeEventInit } from "./credential-event.ts";
export type { Endpoint, EndRoleRecord, LocationRecord } from "./endpoint-discovery.ts";
export { resolveEndRole, resolveLocation } from "./endpoint-discovery.ts";
export type { WitnessEndpoint } from "./kawa.ts";
export { submitToWitnesses } from "./kawa.ts";
export type {
  InceptArgs,
  InceptEvent,
  InteractArgs,
  InteractEvent,
  KeyEvent,
  KeyEventBody,
  KeyState,
  RotateArgs,
  RotateEvent,
} from "./key-event.ts";
export { KeyEventLog } from "./key-event-log.ts";
export type { GenerateKeyPairOptions, KeyPair } from "./keys.ts";
export type { MailboxClientOptions } from "./mailbox-client.ts";
export { MailboxClient } from "./mailbox-client.ts";
export type { ReceiptEventBody, ReceiptEventInit } from "./receipt-event.ts";
export type { RegistryInceptEvent, RegistryInceptEventInit } from "./registry-event.ts";
export type {
  ExchangeEvent,
  ExchangeEventInit,
  QueryEvent,
  QueryEventInit,
  ReplyEvent,
  ReplyEventInit,
} from "./routed-event.ts";
export type { SignOptions } from "./sign.ts";
export { sign } from "./sign.ts";
export type { Threshold } from "./threshold.ts";
export type { VerifyOptions, VerifyResult } from "./verify.ts";

export const keri = {
  // Key events
  incept,
  interact,
  rotate,
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
    verify,
    formatDate,
    generateKeyPair,
    digest,
  },
};
