import { encodeText, Matter, Message, VersionString } from "cesr";
import { saidify } from "./said.ts";
import type { VerifyResult } from "./verify.ts";

export const DUMMY_VERSION = VersionString.encode({ protocol: "KERI", legacy: true, kind: "JSON" });

/** Placeholder occupying a SAID field while the digest over the event is computed. */
export const DUMMY_SAID = "#".repeat(44);

export function formatDate(date: Date): string {
  return date.toISOString().replace("Z", "000+00:00");
}

export function randomNonce(): string {
  return encodeText(Matter.from(Matter.Code.Salt_128, crypto.getRandomValues(new Uint8Array(16))));
}

interface EncodeEventArgs {
  labels?: string[];
  protocol?: string;
  legacy?: boolean;
}

export function encodeEvent<T extends Record<string, unknown>>(
  input: T,
  args: EncodeEventArgs = {},
): T & { v: string } {
  const labels = args.labels ?? ["d"];
  const data: Record<string, unknown> = { ...input };

  for (const label of labels) {
    if (!(label in data)) {
      throw new Error(`Input missing label '${label}'`);
    }

    data[label] = DUMMY_SAID;
  }

  const message = new Message({
    v: VersionString.encode({ protocol: args.protocol ?? "KERI", legacy: args.legacy ?? true, kind: "JSON" }),
    ...data,
  });

  return saidify(message.body, labels) as T & { v: string };
}

export interface VerifyEventSaidArgs extends EncodeEventArgs {
  /** Names the event in the error message, e.g. the event type. */
  subject?: string;
}

/**
 * Inverse of {@link encodeEvent}: recompute the SAID labels over `body` and
 * compare them against the ones it carries.
 */
export function verifyEventSaid(body: Record<string, unknown>, args: VerifyEventSaidArgs = {}): VerifyResult {
  const labels = args.labels ?? ["d"];
  const recomputed = encodeEvent(body, args);
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
