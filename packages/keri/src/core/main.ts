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

export { Attachments, Message } from "cesr";
export type { Credential, CredentialBody } from "./credential.ts";
export { createCredential } from "./credential.ts";
export type { IssueEvent, RevokeEvent } from "./credential-event.ts";
export type { Endpoint, EndRoleRecord, LocationRecord } from "./endpoint-discovery.ts";
export { resolveEndRole, resolveLocation } from "./endpoint-discovery.ts";
export { submitToWitnesses } from "./kawa.ts";
export type { InceptEvent, InteractEvent, KeyEvent, KeyEventBody, KeyState, RotateEvent } from "./key-event.ts";
export { KeyEventLog } from "./key-event-log.ts";
export type { KeyPair } from "./keys.ts";
export { MailboxClient } from "./mailbox-client.ts";
export type { RegistryInceptEvent } from "./registry-event.ts";
export type { ExchangeEvent, ReplyEvent } from "./routed-event.ts";
export { sign } from "./sign.ts";
export type { VerifyResult } from "./verify.ts";

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
