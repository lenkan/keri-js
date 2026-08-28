import { Message } from "../cesr/main.ts";
import { DUMMY_SAID, DUMMY_VERSION, encodeEvent, saidify, verifyEventSaid } from "../events/main.ts";
import type { VerifyResult } from "../keys/main.ts";

export interface CredentialArgs {
  /**
   * Salty nonce
   */
  u?: string;
  i: string;
  ri: string;
  s: string;
  a: {
    i?: string;
    dt?: string;
    [key: string]: string | Record<string, unknown> | undefined;
  };
  r?: Record<string, unknown>;
  e?: Record<string, unknown>;
}

export interface CredentialSubject {
  /**
   * Subject SAID
   */
  d: string;

  /**
   * Issuee AID
   */
  i?: string;

  /**
   * Issuance timestamp
   */
  dt?: string;

  [key: string]: string | undefined;
}

export interface CredentialRules {
  /**
   * Rules SAID
   */
  d: string;
  [key: string]: string | Record<string, unknown> | undefined;
}

export interface CredentialEdges {
  /**
   * Edges SAID
   */
  d: string;
  [key: string]: string | Record<string, unknown> | undefined;
}

export type CredentialBody = {
  v: string;

  /**
   * Credential SAID
   */
  d: string;

  /**
   * Issuer AID
   */
  i: string;

  /**
   * Registry AID
   */
  ri: string;

  /**
   * Schema SAID
   */
  s: string;

  /**
   * Credential subject (claims)
   */
  a: CredentialSubject;

  /**
   * Credential rules
   */
  r: CredentialRules;

  /**
   * Credential edges
   */
  e?: CredentialEdges;
};

export interface CredentialSaidResult {
  /**
   * Whether the top level `d` recomputes over the body.
   */
  body: VerifyResult;

  /**
   * Whether each disclosed `a` / `e` / `r` block's `d` recomputes over that
   * block, or null when the credential discloses no section to recompute.
   */
  sections: VerifyResult | null;
}

const SECTION_LABELS = ["a", "e", "r"];

// `d` is the section SAID, `i` the issuee, `dt` the issuance date and `u` the
// blinding nonce — none of them claims the issuer is asserting.
const ATTRIBUTE_METADATA = ["d", "i", "dt", "u"];

function attributes(body: CredentialBody): Record<string, unknown> | null {
  const section = body.a as unknown;
  // Compact and partially disclosed credentials carry a bare SAID string here.
  return typeof section === "object" && section !== null ? (section as Record<string, unknown>) : null;
}

/** The claims an ACDC asserts, with the attribute section's metadata removed. */
export function disclosedAttributes(body: CredentialBody): [string, unknown][] {
  return Object.entries(attributes(body) ?? {}).filter(([key]) => !ATTRIBUTE_METADATA.includes(key));
}

/** The AID the credential was issued to, when the attribute section names one. */
export function credentialIssuee(body: CredentialBody): string | null {
  const value = attributes(body)?.i;
  return typeof value === "string" ? value : null;
}

/**
 * Inverse of {@link createCredential}. The two must stay in lockstep.
 *
 * For an expanded credential the top level digest already covers the section
 * contents, so `sections` is not an additional integrity check — it localises a
 * failure to the section that changed, which a single top level mismatch cannot.
 */
export function verifyCredentialSaid(body: CredentialBody): CredentialSaidResult {
  return { body: verifyEventSaid(body, { labels: ["d"] }), sections: verifySectionSaids(body) };
}

function verifySectionSaids(body: CredentialBody): VerifyResult | null {
  let disclosed = false;

  for (const label of SECTION_LABELS) {
    const section = (body as Record<string, unknown>)[label];

    // A compact or partially disclosed section is a bare SAID string with nothing to recompute.
    if (section === undefined || typeof section === "string") {
      continue;
    }

    if (typeof section !== "object" || section === null || Array.isArray(section)) {
      return { ok: false, error: `Section '${label}' is not an object` };
    }

    disclosed = true;
    const block = section as Record<string, unknown>;
    if (typeof block.d !== "string") {
      return { ok: false, error: `Section '${label}' has no SAID` };
    }

    // Spread first so `d` keeps its original key position; JSON.stringify is order sensitive.
    const recomputed = saidify({ ...block, d: DUMMY_SAID }, ["d"]);
    if (recomputed.d !== block.d) {
      return { ok: false, error: `Section '${label}' SAID mismatch: expected ${String(recomputed.d)}, got ${block.d}` };
    }
  }

  return disclosed ? { ok: true } : null;
}

export function createCredential(data: CredentialArgs): Message<CredentialBody> {
  const body = encodeEvent<CredentialBody>(
    {
      v: DUMMY_VERSION,
      d: DUMMY_SAID,
      ...(data.u && { u: data.u }),
      i: data.i,
      ri: data.ri,
      s: data.s,
      a: saidify({ d: DUMMY_SAID, ...data.a }, ["d"]),
      ...(data.e && { e: saidify({ d: DUMMY_SAID, ...data.e }, ["d"]) }),
      r: saidify({ d: DUMMY_SAID, ...data.r }, ["d"]),
    },
    { labels: ["d"], protocol: "ACDC" },
  );

  return new Message<CredentialBody>(body);
}

export function isCredential(message: Message): message is Message<CredentialBody> {
  return message.version.protocol === "ACDC";
}
