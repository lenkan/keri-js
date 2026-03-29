import { exchange, query, reply } from "./routed-event.ts";
import { receipt } from "./receipt-event.ts";
import { incept, interact, rotate } from "./key-event.ts";
import { incept as registry } from "./registry-event.ts";
import { issue, revoke } from "./credential-event.ts";
import { formatDate } from "./events.ts";
import { generateKeyPair } from "./keys.ts";
import { createCredential } from "./credential.ts";
import { sign } from "./sign.ts";
import { verify } from "./verify.ts";
import { digest } from "./digest.ts";

export { sign } from "./sign.ts";
export { Message, Attachments } from "cesr";

export type { KeyEvent } from "./key-event.ts";
export { KeyEventLog } from "./key-event-log.ts";
export type { KeyState, InceptEvent, InteractEvent, RotateEvent, KeyEventBody } from "./key-event.ts";
export type { KeyPair } from "./keys.ts";
export type { RegistryInceptEvent } from "./registry-event.ts";
export type { IssueEvent, RevokeEvent } from "./credential-event.ts";
export type { ReplyEvent, ExchangeEvent } from "./routed-event.ts";
export { createCredential } from "./credential.ts";
export type { EndRoleRecord, LocationRecord, Endpoint } from "./endpoint-discovery.ts";
export { resolveEndRole, resolveLocation } from "./endpoint-discovery.ts";
export type { Credential, CredentialBody } from "./credential.ts";
export type { VerifyResult } from "./verify.ts";

export { MailboxClient } from "./mailbox-client.ts";
export { submitToWitnesses } from "./kawa.ts";

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
