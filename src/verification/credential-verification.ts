import type { Message } from "../cesr/main.ts";
import { type CredentialBody, credentialIssuee, verifyCredentialSaid } from "../credentials/internal.ts";
import { KeyEventLog, type KeyState } from "../key-events/main.ts";
import type { VerifyResult } from "../keys/main.ts";
import type {
  CredentialStatus,
  IssueEventBody,
  RegistryEventBody,
  RegistryInceptEventBody,
  RevokeEventBody,
} from "../registries/internal.ts";
import { resolveCredentialTel, verifyRegistryEventAnchor, verifyRegistryEventSaid } from "../registries/internal.ts";
import type { EventIndex } from "./event-index.ts";

export type CheckStatus =
  | "passed"
  | "failed"
  /** A prerequisite check failed, so this one could not be evaluated. */
  | "skipped"
  /** Nothing in the input triggers this check. */
  | "not-applicable"
  /** Out of scope for offline verification. */
  | "unchecked";

export type CredentialCheckId =
  | "acdc-said"
  | "acdc-section-saids"
  | "issuer-kel"
  | "registry-inception"
  | "registry-anchor"
  | "issuance"
  | "issuance-anchor"
  | "revocation-anchor"
  | "edges"
  | "schema";

export interface CredentialCheck {
  id: CredentialCheckId;
  status: CheckStatus;
  /** Always set unless the status is "passed". */
  detail?: string;
}

/** An `e` block entry, resolved against the credentials in the same index. */
export interface CredentialEdge {
  /** The edge's label in the `e` block, e.g. "qvi". */
  label: string;
  /** SAID of the credential the edge points at. */
  said: string;
  /** Whether that credential is present in the index and verified. */
  ok: boolean;
}

export interface CredentialVerification {
  credential: Message<CredentialBody>;
  said: string;
  issuer: string;
  /** The AID the credential was issued to, when the attribute section names one. */
  issuee: string | null;
  registry: string;
  schema: string;
  /** Null when the issuer KEL did not verify. */
  issuerState: KeyState | null;
  issuedAt: string | null;
  revokedAt: string | null;
  status: CredentialStatus;
  /** Resolved `e` block entries, empty when the credential has no edges. */
  edges: CredentialEdge[];
  /** No check is "failed" or "skipped". Revocation is reported by `status`, not here. */
  ok: boolean;
  /** Every `CredentialCheckId`, always present, in display order. */
  checks: CredentialCheck[];
}

/**
 * Verify every credential carried by `index`, each exactly once.
 *
 * Issuer KELs are verified once per AID and shared across credentials, and an
 * edge referencing another credential in the same index resolves against the
 * result computed for it here.
 */
export function verifyCredentials(
  index: EventIndex,
  context: VerificationContext = newContext(index),
): CredentialVerification[] {
  return index.credentials.map((credential) => resolve(context, credential.body.d) as CredentialVerification);
}

/**
 * Verify one credential in `index` by SAID.
 *
 * Throws only on malformed input — a credential that fails verification is a
 * normal result, reported through `checks`.
 */
export function verifyCredential(index: EventIndex, said: string): CredentialVerification {
  const result = resolve(newContext(index), said);
  if (!result) {
    throw new TypeError(`No credential ${said} in index`);
  }
  return result;
}

/**
 * Per-run caches. Share one across calls and each AID's KEL is verified once
 * rather than once per caller — a KEL verification is a signature check per
 * signature per event, so the saving is not marginal.
 */
export interface VerificationContext {
  index: EventIndex;
  logs: Map<string, KeyEventLog | string>;
  results: Map<string, CredentialVerification>;
  visiting: Set<string>;
}

type Context = VerificationContext;

export function newContext(index: EventIndex): VerificationContext {
  return { index, logs: new Map(), results: new Map(), visiting: new Set() };
}

/** Verified KEL for `aid`, or the reason it could not be built. Cached per run. */
export function issuerLog(context: Context, aid: string): KeyEventLog | string {
  const cached = context.logs.get(aid);
  if (cached !== undefined) {
    return cached;
  }

  const keyEvents = context.index.keyEvents(aid);
  let result: KeyEventLog | string;
  if (keyEvents.length === 0) {
    result = `No key events for issuer ${aid}`;
  } else {
    try {
      // Non-empty input means every event was appended, so `state` is populated.
      result = KeyEventLog.fromMessages(keyEvents);
    } catch (error) {
      result = describe(error);
    }
  }

  context.logs.set(aid, result);
  return result;
}

function resolve(context: Context, said: string): CredentialVerification | null {
  const cached = context.results.get(said);
  if (cached) {
    return cached;
  }

  const credential = context.index.credential(said);
  if (!credential) {
    return null;
  }

  const result = verify(context, credential);
  context.results.set(said, result);
  return result;
}

function verify(context: Context, credential: Message<CredentialBody>): CredentialVerification {
  const body = credential.body;

  if (credential.version.protocol !== "ACDC") {
    throw new TypeError(`Not an ACDC message: protocol=${credential.version.protocol}`);
  }
  if (typeof body.d !== "string" || typeof body.i !== "string" || typeof body.ri !== "string") {
    throw new TypeError("Malformed ACDC: 'd', 'i' and 'ri' must be strings");
  }

  const tel = resolveCredentialTel(context.index.registryEvents(body.ri), {
    credential: body.d,
    registry: body.ri,
  });

  const said = verifyCredentialSaid(body);
  const checks: CredentialCheck[] = [
    toCheck("acdc-said", said.body),
    said.sections
      ? toCheck("acdc-section-saids", said.sections)
      : { id: "acdc-section-saids", status: "not-applicable", detail: "No section is disclosed" },
  ];

  // The index groups key events by their own `i`, so a log found for `body.i`
  // belongs to the issuer by construction — there is no binding left to check.
  const log = issuerLog(context, body.i);
  const issuer = typeof log === "string" ? null : log;
  checks.push(
    typeof log === "string"
      ? { id: "issuer-kel", status: "failed", detail: log }
      : { id: "issuer-kel", status: "passed" },
  );

  const registryCheck: CredentialCheck = tel.registry
    ? toCheck("registry-inception", verifyRegistryInception(tel.registry.body, body))
    : { id: "registry-inception", status: "failed", detail: `No vcp event for registry ${body.ri}` };
  checks.push(registryCheck);
  checks.push(anchorCheck("registry-anchor", tel.registry, issuer, registryCheck));

  const issuanceCheck: CredentialCheck = tel.issuance
    ? toCheck("issuance", verifyIssuance(tel.issuance.body, body, credential))
    : { id: "issuance", status: "failed", detail: `No iss event for credential ${body.d}` };
  checks.push(issuanceCheck);

  const issuanceAnchorCheck = anchorCheck("issuance-anchor", tel.issuance, issuer, issuanceCheck);
  checks.push(issuanceAnchorCheck);

  checks.push(verifyRevocation(tel.revocation, tel.issuance, issuer));

  const { edges, check: edgeCheck } = verifyEdges(context, body);
  checks.push(edgeCheck);

  checks.push({ id: "schema", status: "unchecked", detail: "Schema document is not available offline" });

  const issued = issuanceCheck.status === "passed" && issuanceAnchorCheck.status === "passed";
  const status: CredentialStatus = tel.status === "issued" && !issued ? "unknown" : tel.status;

  return {
    credential,
    said: body.d,
    issuer: body.i,
    issuee: credentialIssuee(body),
    registry: body.ri,
    schema: body.s,
    issuerState: issuer?.state ?? null,
    issuedAt: tel.issuance?.body.dt ?? null,
    revokedAt: tel.revocation?.body.dt ?? null,
    status,
    edges,
    ok: checks.every((c) => c.status !== "failed" && c.status !== "skipped"),
    checks,
  };
}

interface EdgeRef {
  label: string;
  n: string;
  s?: string;
}

/**
 * Resolve each `e` entry against the index. An edge is satisfied when the
 * credential it names is present, verifies, and matches the schema the edge
 * declares.
 */
function verifyEdges(context: Context, body: CredentialBody): { edges: CredentialEdge[]; check: CredentialCheck } {
  const id: CredentialCheckId = "edges";
  const refs = edgeRefs(body);

  if (refs.length === 0) {
    return { edges: [], check: { id, status: "not-applicable", detail: "Credential has no edges" } };
  }

  const edges: CredentialEdge[] = [];
  const failures: string[] = [];
  context.visiting.add(body.d);

  for (const ref of refs) {
    let ok = false;

    if (context.visiting.has(ref.n)) {
      failures.push(`'${ref.label}' forms a cycle back to ${ref.n}`);
    } else {
      const target = resolve(context, ref.n);
      if (!target) {
        failures.push(`'${ref.label}' references ${ref.n}, which is not in the stream`);
      } else if (ref.s !== undefined && target.schema !== ref.s) {
        failures.push(`'${ref.label}' declares schema ${ref.s}, but ${ref.n} uses ${target.schema}`);
      } else if (!target.ok) {
        failures.push(`'${ref.label}' references ${ref.n}, which did not verify`);
      } else if (target.status === "revoked") {
        failures.push(`'${ref.label}' references ${ref.n}, which is revoked`);
      } else {
        ok = true;
      }
    }

    edges.push({ label: ref.label, said: ref.n, ok });
  }

  context.visiting.delete(body.d);

  return {
    edges,
    check: failures.length === 0 ? { id, status: "passed" } : { id, status: "failed", detail: failures.join("; ") },
  };
}

function edgeRefs(body: CredentialBody): EdgeRef[] {
  const section = body.e as unknown;
  if (typeof section !== "object" || section === null) {
    return [];
  }

  const refs: EdgeRef[] = [];
  for (const [label, value] of Object.entries(section as Record<string, unknown>)) {
    // `d` is the section SAID and `o` an operator, neither is an edge.
    if (label === "d" || label === "o" || typeof value !== "object" || value === null) {
      continue;
    }
    const edge = value as Record<string, unknown>;
    if (typeof edge.n === "string") {
      refs.push({ label, n: edge.n, s: typeof edge.s === "string" ? edge.s : undefined });
    }
  }

  return refs;
}

const NO_KEL = "Issuer KEL did not verify";

function anchorCheck(
  id: CredentialCheckId,
  event: Message<RegistryEventBody> | null,
  issuer: KeyEventLog | null,
  prerequisite: CredentialCheck,
): CredentialCheck {
  if (issuer === null) {
    return { id, status: "skipped", detail: NO_KEL };
  }
  if (event === null || prerequisite.status !== "passed") {
    return { id, status: "skipped", detail: `${prerequisite.id} did not verify` };
  }
  return toCheck(id, verifyRegistryEventAnchor(event, issuer));
}

function toCheck(id: CredentialCheckId, result: VerifyResult): CredentialCheck {
  return result.ok ? { id, status: "passed" } : { id, status: "failed", detail: result.error };
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function verifyRegistryInception(vcp: RegistryInceptEventBody, body: CredentialBody): VerifyResult {
  const said = verifyRegistryEventSaid(vcp);
  if (!said.ok) {
    return said;
  }
  if (vcp.ii !== body.i) {
    return { ok: false, error: `Registry ${vcp.i} is owned by ${vcp.ii}, not by issuer ${body.i}` };
  }
  return { ok: true };
}

function verifyIssuance(iss: IssueEventBody, body: CredentialBody, credential: Message<CredentialBody>): VerifyResult {
  const said = verifyRegistryEventSaid(iss);
  if (!said.ok) {
    return said;
  }

  // The ACDC's own seal source triple names the TEL event it belongs to. Checking
  // it rules out a valid iss event for a different credential being substituted.
  for (const triple of credential.attachments.SealSourceTriples) {
    if (triple.prefix === body.d && triple.digest !== iss.d) {
      return { ok: false, error: `Credential references issuance ${triple.digest}, but ${iss.d} was presented` };
    }
  }

  return { ok: true };
}

function verifyRevocation(
  revocation: Message<RevokeEventBody> | null,
  issuance: Message<IssueEventBody> | null,
  issuer: KeyEventLog | null,
): CredentialCheck {
  const id: CredentialCheckId = "revocation-anchor";

  if (!revocation) {
    return { id, status: "not-applicable", detail: "No revocation event presented" };
  }

  const said = verifyRegistryEventSaid(revocation.body);
  if (!said.ok) {
    return { id, status: "failed", detail: said.error };
  }

  if (issuance && revocation.body.p !== issuance.body.d) {
    return {
      id,
      status: "failed",
      detail: `Revocation prior is ${revocation.body.p}, issuance is ${issuance.body.d}`,
    };
  }

  return anchorCheck(id, revocation, issuer, { id, status: "passed" });
}
