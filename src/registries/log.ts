/**
 * Verification of registry events (`vcp`, `iss`, `rev`) — a registry's
 * Transaction Event Log.
 *
 * These are functions rather than a `KeyEventLog`-style class: a TEL carries no
 * reduced state for each event to consult, and callers need each failure
 * reported separately rather than collapsed into a single throw.
 *
 * TEL events are not signed. Authenticity comes from the seal that anchors them
 * into the issuer's signed KEL, which is what {@link verifyRegistryEventAnchor}
 * checks.
 */

import type { Message } from "../cesr/main.ts";
import { verifyEventSaid } from "../events/main.ts";
import { findSealAnchor, type KeyEventLog } from "../key-events/internal.ts";
import type { VerifyResult } from "../keys/main.ts";
import type { IssueEventBody, RevokeEventBody } from "./credential-event.ts";
import type { RegistryInceptEventBody } from "./registry-event.ts";

export type RegistryEventBody = RegistryInceptEventBody | IssueEventBody | RevokeEventBody;

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

export function isRegistryEvent(message: Message): message is Message<RegistryEventBody> {
  return isTelEventType(message.body.t);
}

export function verifyRegistryEventSaid(body: RegistryEventBody): VerifyResult {
  const labels = SAID_LABELS[body.t];
  if (!labels) {
    return { ok: false, error: `Unsupported registry event type: ${body.t}` };
  }

  return verifyEventSaid(body, { labels, subject: body.t });
}

export function verifyRegistryEventAnchor(message: Message<RegistryEventBody>, issuer: KeyEventLog): VerifyResult {
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
  events: Iterable<Message<RegistryEventBody>>,
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
