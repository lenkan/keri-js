import { sha256 } from "@noble/hashes/sha2.js";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { encodeText } from "cesr";
import { decodeUtf8, encodeBase64Url, encodeUtf8 } from "cesr/encoding";
import type { KeyEventLog, KeyState } from "keri";

/**
 * Every key event the verifier has ever seen, per AID — durable, unlike the
 * login sessions. Remembering first-seen events across sessions is what makes
 * duplicity detectable: a later submission carrying a different event at the
 * same `(aid, sn)` is a fork, not an update.
 */
export interface KeyEventStore {
  getEvent(aid: string, sn: bigint): Promise<StoredKeyEvent | null>;
  putEvent(aid: string, sn: bigint, event: StoredKeyEvent): Promise<void>;
}

export interface StoredKeyEvent {
  digest: string;
  raw: string;
}

export type LoginRecord =
  | { phase: "challenged"; aid: string; state: KeyState; words: string[]; error?: string }
  | { phase: "authenticated"; aid: string; state: KeyState; authenticatedAt: string };

export interface Identity {
  aid: string;
  sequenceNumber: number;
  signingKeys: string[];
  signingThreshold: KeyState["signingThreshold"];
  witnesses: string[];
  lastEstablishment: KeyState["lastEstablishment"];
  authenticatedAt: string;
}

export function identityOf(record: LoginRecord & { phase: "authenticated" }): Identity {
  return {
    aid: record.aid,
    sequenceNumber: Number.parseInt(record.state.lastEvent.s, 16),
    signingKeys: record.state.signingKeys,
    signingThreshold: record.state.signingThreshold,
    witnesses: record.state.backers,
    lastEstablishment: record.state.lastEstablishment,
    authenticatedAt: record.authenticatedAt,
  };
}

const WORD_COUNT = 12;

// 2048 divides 2^16, so the modulo is bias-free. kli challenge respond accepts
// arbitrary words, but real BIP39 words keep the UX identical to
// `kli challenge generate`.
export function generateWords(): string[] {
  const indexes = crypto.getRandomValues(new Uint16Array(WORD_COUNT));
  return Array.from(indexes, (index) => wordlist[index % wordlist.length]);
}

/** KV key for the words → session correlation: the response exn carries no token. */
export function wordsKey(words: string[]): string {
  return encodeBase64Url(sha256(encodeUtf8(words.join(" "))));
}

export type RecordKeyEventsResult = { ok: true } | { ok: false; aid: string; sn: bigint };

/**
 * Persist a submitted KEL into the store, first-seen wins. A stored event whose
 * digest differs from the submission's at the same `(aid, sn)` is duplicity —
 * nothing is written and the conflict is returned.
 *
 * Not atomic: two concurrent first submissions can race a first-seen slot. Fine
 * while duplicity is only refused; move to storage with CAS before evidence
 * handling depends on it.
 */
export async function recordKeyEvents(store: KeyEventStore, log: KeyEventLog): Promise<RecordKeyEventsResult> {
  const aid = log.state.identifier;
  const events = log.events.map((message) => ({ message, sn: BigInt(`0x${message.body.s}`), digest: message.body.d }));
  const seen = await Promise.all(events.map((event) => store.getEvent(aid, event.sn)));

  const conflict = events.findIndex((event, index) => seen[index] && seen[index].digest !== event.digest);
  if (conflict !== -1) {
    return { ok: false, aid, sn: events[conflict].sn };
  }

  await Promise.all(
    events
      .filter((_, index) => !seen[index])
      .map((event) =>
        store.putEvent(aid, event.sn, {
          digest: event.digest,
          raw: decodeUtf8(event.message.raw) + encodeText(event.message.attachments.frames()),
        }),
      ),
  );

  return { ok: true };
}
