import { sha256 } from "@noble/hashes/sha2.js";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { encodeText } from "cesr";
import { encodeBase64Url, encodeUtf8 } from "cesr/encoding";
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
  getHead(aid: string): Promise<KeyEventHead | null>;
  putHead(aid: string, head: KeyEventHead): Promise<void>;
}

export interface StoredKeyEvent {
  digest: string;
  raw: string;
}

export interface KeyEventHead {
  latestSn: string;
  latestDigest: string;
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
  const events = log.events.map((message) => ({
    aid: message.body.i,
    sn: BigInt(`0x${message.body.s}`),
    digest: message.body.d,
    raw: new TextDecoder().decode(message.raw) + encodeText(message.attachments.frames()),
  }));

  for (const event of events) {
    const seen = await store.getEvent(event.aid, event.sn);
    if (seen && seen.digest !== event.digest) {
      return { ok: false, aid: event.aid, sn: event.sn };
    }
  }

  for (const event of events) {
    const seen = await store.getEvent(event.aid, event.sn);
    if (!seen) {
      await store.putEvent(event.aid, event.sn, { digest: event.digest, raw: event.raw });
    }

    const head = await store.getHead(event.aid);
    if (!head || BigInt(`0x${head.latestSn}`) < event.sn) {
      await store.putHead(event.aid, { latestSn: event.sn.toString(16), latestDigest: event.digest });
    }
  }

  return { ok: true };
}
