import { encodeText, Matter, Message, VersionString } from "cesr";
import { saidify } from "./said.ts";
import type { VerifyResult } from "./verify.ts";

/** KERI protocol version. v1 uses the legacy 17-char version string, v2 the 16-char one. */
export type ProtocolVersion = 1 | 2;

/** Placeholder occupying a SAID field while the digest over the event is computed. */
export const DUMMY_SAID = "#".repeat(44);

/** Placeholder `v` field; {@link encodeEvent} always replaces it with the real version string. */
export const DUMMY_VERSION = VersionString.KERI_LEGACY;

export function versionString(protocol: string, version: ProtocolVersion): string {
  if (protocol === "ACDC") {
    return version === 2 ? VersionString.ACDC : VersionString.ACDC_LEGACY;
  }

  return version === 2 ? VersionString.KERI : VersionString.KERI_LEGACY;
}

export function formatDate(date: Date): string {
  return date.toISOString().replace("Z", "000+00:00");
}

export function randomNonce(): string {
  return encodeText(Matter.from(Matter.Code.Salt_128, crypto.getRandomValues(new Uint8Array(16))));
}

export interface EncodeEventArgs {
  labels?: string[];
  protocol?: string;
  version?: ProtocolVersion;
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
    v: versionString(args.protocol ?? "KERI", args.version ?? 1),
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
 * Protocol and version come from the body's own `v` field, so a v2 event is
 * re-encoded as v2 rather than against the v1 default.
 */
export function verifyEventSaid(body: Record<string, unknown>, args: VerifyEventSaidArgs = {}): VerifyResult {
  const labels = args.labels ?? ["d"];
  const version = VersionString.parse(body.v as string);
  const recomputed = encodeEvent(body, {
    labels,
    protocol: version.protocol,
    version: version.legacy ? 1 : 2,
  });
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
