/**
 * Verification of registry transaction events (`vcp`, `iss`, `rev`).
 *
 * These are functions rather than a `KeyEventLog`-style class: a TEL carries no
 * reduced state for each event to consult, and callers need each failure
 * reported separately rather than collapsed into a single throw.
 *
 * TEL events are not signed. Authenticity comes from the seal that anchors them
 * into the issuer's signed KEL, which is what {@link verifyTransactionEventAnchor}
 * checks.
 */

import type { Message } from "cesr";
import type { IssueEventBody, RevokeEventBody } from "./credential-event.ts";
import { verifyEventSaid } from "./events.ts";
import type { KeyEventLog } from "./key-event-log.ts";
import { findSealAnchor } from "./key-event-log.ts";
import type { RegistryInceptEventBody } from "./registry-event.ts";
import type { VerifyResult } from "./verify.ts";

export type TransactionEventBody = RegistryInceptEventBody | IssueEventBody | RevokeEventBody;

export type CredentialStatus = "issued" | "revoked" | "unknown";

export interface CredentialTel {
  registry: Message<RegistryInceptEventBody> | null;
  issuance: Message<IssueEventBody> | null;
  revocation: Message<RevokeEventBody> | null;
  status: CredentialStatus;
}

export interface ResolveCredentialTelArgs {
  credential: string;
  registry: string;
}

const SAID_LABELS: Record<string, string[]> = {
  vcp: ["d", "i"],
  iss: ["d"],
  rev: ["d"],
};

export function isTelEventType(t: unknown): boolean {
  return t === "vcp" || t === "iss" || t === "rev";
}

export function verifyTransactionEventSaid(body: TransactionEventBody): VerifyResult {
  const labels = SAID_LABELS[body.t];
  if (!labels) {
    return { ok: false, error: `Unsupported transaction event type: ${body.t}` };
  }

  return verifyEventSaid(body, { labels, subject: body.t });
}

export function verifyTransactionEventAnchor(
  message: Message<TransactionEventBody>,
  issuer: KeyEventLog,
): VerifyResult {
  const body = message.body;
  const failure = findSealAnchor(body, message.attachments, {
    identifier: issuer.state.identifier,
    events: issuer.events,
  });

  switch (failure?.kind) {
    case "hint-missing":
      return { ok: false, error: `Anchoring event not in issuer KEL: s=${failure.snu} d=${failure.digest}` };
    case "hint-unanchored":
      return {
        ok: false,
        error: `Issuer event ${failure.digest} does not anchor ${body.t} ${body.d}: no matching seal in a[]`,
      };
    case "unanchored":
      return { ok: false, error: `No anchoring event in issuer KEL for ${body.t} ${body.d}` };
    default:
      return { ok: true };
  }
}

export function resolveCredentialTel(
  events: Iterable<Message<TransactionEventBody>>,
  args: ResolveCredentialTelArgs,
): CredentialTel {
  let registry: Message<RegistryInceptEventBody> | null = null;
  let issuance: Message<IssueEventBody> | null = null;
  let revocation: Message<RevokeEventBody> | null = null;

  for (const message of events) {
    const body = message.body;
    if (body.t === "vcp" && body.i === args.registry) {
      registry = message as Message<RegistryInceptEventBody>;
    } else if (body.t === "iss" && body.i === args.credential && body.ri === args.registry) {
      issuance = message as Message<IssueEventBody>;
    } else if (body.t === "rev" && body.i === args.credential && body.ri === args.registry) {
      revocation = message as Message<RevokeEventBody>;
    }
  }

  // Status reflects the presence of a revocation even when that revocation fails
  // its own checks — never report "issued" while a revocation is being claimed.
  const status: CredentialStatus = revocation ? "revoked" : issuance ? "issued" : "unknown";

  return { registry, issuance, revocation, status };
}
