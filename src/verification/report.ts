import { type ParseInput, parse } from "../cesr/main.ts";
import type { KeyState } from "../key-events/main.ts";
import { type RegistryInceptEventBody, verifyTransactionEventSaid } from "../transaction-events/internal.ts";
import type { CredentialVerification, VerificationContext } from "./credential-verification.ts";
import { issuerLog, newContext, verifyCredentials } from "./credential-verification.ts";
import { EventIndex } from "./event-index.ts";

export interface IdentifierVerification {
  aid: string;
  /** Null when the KEL did not verify. */
  state: KeyState | null;
  ok: boolean;
  /** Always set when `ok` is false. */
  detail?: string;
}

export interface RegistryVerification {
  registry: string;
  /** The AID named by the registry inception's `ii`, when it verified. */
  issuer: string | null;
  ok: boolean;
  /** Always set when `ok` is false. */
  detail?: string;
}

export interface VerifyReport {
  identifiers: IdentifierVerification[];
  registries: RegistryVerification[];
  credentials: CredentialVerification[];
  /** Every failure across the three, flattened — the "just tell me" path. */
  problems: string[];
}

/**
 * Read a CESR stream and group what it carries.
 *
 * Separate from {@link verify} because parsing is streaming and forward-only
 * while verification needs the settled set: a stream is a bag, so a credential
 * can arrive before its issuance event and key events need sorting once they
 * have all been seen.
 */
export async function collect(input: ParseInput): Promise<EventIndex> {
  return new EventIndex(await Array.fromAsync(parse(input)));
}

/**
 * Verify everything in `index` — key event logs, registries and credentials.
 *
 * Never throws on a verification failure; a message that does not check out is
 * a normal result reported through `ok`/`detail`. Context the stream does not
 * carry (a delegator's KEL, a credential an edge points at) is reported the
 * same way, so a caller holding storage can seed the index and try again.
 */
export function verify(index: EventIndex): VerifyReport {
  // One context across all three passes: without it every issuer's KEL is
  // verified twice, once here and once inside verifyCredentials.
  const context = newContext(index);
  const identifiers = index.identifiers.map((aid) => verifyIdentifier(context, aid));
  const registries = index.registries.map((registry) => verifyRegistry(index, registry));
  const credentials = verifyCredentials(index, context);

  const problems: string[] = [];

  for (const identifier of identifiers) {
    if (!identifier.ok) {
      problems.push(`Identifier ${identifier.aid}: ${identifier.detail}`);
    }
  }

  for (const registry of registries) {
    if (!registry.ok) {
      problems.push(`Registry ${registry.registry}: ${registry.detail}`);
    }
  }

  for (const credential of credentials) {
    for (const check of credential.checks) {
      if (check.status === "failed" || check.status === "skipped") {
        problems.push(`Credential ${credential.said}: ${check.id} ${check.status} — ${check.detail}`);
      }
    }
  }

  return { identifiers, registries, credentials, problems };
}

function verifyIdentifier(context: VerificationContext, aid: string): IdentifierVerification {
  const log = issuerLog(context, aid);

  return typeof log === "string" ? { aid, state: null, ok: false, detail: log } : { aid, state: log.state, ok: true };
}

function verifyRegistry(index: EventIndex, registry: string): RegistryVerification {
  const inception = index.transactionEvents(registry).find((event) => event.body.t === "vcp");

  if (!inception) {
    return { registry, issuer: null, ok: false, detail: "No registry inception event" };
  }

  const said = verifyTransactionEventSaid(inception.body);
  if (!said.ok) {
    return { registry, issuer: null, ok: false, detail: said.error };
  }

  return { registry, issuer: (inception.body as RegistryInceptEventBody).ii, ok: true };
}
