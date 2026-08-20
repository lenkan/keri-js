import { encodeText, Matter, Message, VersionString } from "cesr";
import { saidify } from "./said.ts";
import type { VerifyResult } from "./verify.ts";

/** Placeholder occupying a SAID field while the digest over the event is computed. */
export const DUMMY_SAID = "#".repeat(44);

/** Placeholder `v` field; {@link encodeEvent} always replaces it with the real version string. */
export const DUMMY_VERSION = VersionString.KERI_LEGACY;

export function formatDate(date: Date): string {
  return date.toISOString().replace("Z", "000+00:00");
}

export function randomNonce(): string {
  return encodeText(Matter.from(Matter.Code.Salt_128, crypto.getRandomValues(new Uint8Array(16))));
}

export interface EncodeEventArgs {
  labels?: string[];
  protocol?: string;
  /**
   * Version string to emit, verbatim. Defaults to the protocol's v1.
   *
   * Passed through rather than reduced to a version number so that re-encoding
   * an existing body reproduces its exact `v` — minor version and serialization
   * kind included, which a SAID is computed over.
   */
  version?: string;
}

export function encodeEvent<T extends Record<string, unknown>>(
  input: T,
  args: EncodeEventArgs = {},
): T & { v: string } {
  const labels = args.labels ?? ["d"];
  // `v` is dropped rather than spread: it is computed here, and letting the
  // input's placeholder through would silently override the requested version.
  const { v: _placeholder, ...rest } = input;
  const data: Record<string, unknown> = { ...rest };

  for (const label of labels) {
    if (!(label in data)) {
      throw new Error(`Input missing label '${label}'`);
    }

    data[label] = DUMMY_SAID;
  }

  const message = new Message({
    v: args.version ?? (args.protocol === "ACDC" ? VersionString.ACDC_LEGACY : VersionString.KERI_LEGACY),
    ...data,
  });

  return saidify(message.body, labels) as T & { v: string };
}

export interface VerifyEventSaidArgs {
  labels?: string[];
  /** Names the event in the error message, e.g. the event type. */
  subject?: string;
}

/**
 * Inverse of {@link encodeEvent}: recompute the SAID labels over `body` and
 * compare them against the ones it carries.
 *
 * The body's own `v` is re-emitted verbatim. Substituting a canonical version
 * string here would change the bytes the digest is taken over, so any event on
 * a minor version or serialization kind other than the default would be
 * reported as tampered.
 */
export function verifyEventSaid(body: Record<string, unknown>, args: VerifyEventSaidArgs = {}): VerifyResult {
  const labels = args.labels ?? ["d"];
  const recomputed = encodeEvent(body, { labels, version: body.v as string });
  const subject = args.subject ? ` for ${args.subject}` : "";

  for (const label of labels) {
    if (recomputed[label] !== body[label]) {
      return {
        ok: false,
        error: `SAID mismatch on '${label}'${subject}: expected ${String(recomputed[label])}, got ${String(body[label])}`,
      };
    }
  }

  return { ok: true };
}
