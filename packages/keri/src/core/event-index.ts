import { type Attachments, type AttachmentsInit, Message } from "cesr";
import type { CredentialBody } from "./credential.ts";
import type { DipEventBody, KeyEventBody } from "./key-event.ts";
import { isKelEventType } from "./key-event.ts";
import type { ExchangeEventBody } from "./routed-event.ts";
import { embeds } from "./routed-event.ts";
import type { TransactionEventBody } from "./transaction-event-log.ts";
import { isTelEventType } from "./transaction-event-log.ts";

/**
 * The key events, registry events and credentials carried by a CESR stream,
 * grouped by the identifiers they belong to.
 *
 * A stream is a bag of messages, not a credential — one can carry several
 * credentials, several registries, and the KELs of several AIDs. Indexing them
 * together is what lets a chained credential resolve its edges against the
 * other credentials that arrived with it.
 */
export class EventIndex {
  #keyEvents = new Map<string, Message<KeyEventBody>[]>();
  #transactionEvents = new Map<string, Message<TransactionEventBody>[]>();
  #credentials = new Map<string, Message<CredentialBody>>();

  constructor(messages: Iterable<Message>) {
    for (const message of flatten(messages)) {
      if (isKelEventType(message.body.t)) {
        const event = message as Message<KeyEventBody>;
        push(this.#keyEvents, event.body.i, event);
      } else if (isTelEventType(message.body.t)) {
        const event = message as Message<TransactionEventBody>;
        push(this.#transactionEvents, event.body.t === "vcp" ? event.body.i : event.body.ri, event);
      } else if (message.version.protocol === "ACDC") {
        const credential = message as Message<CredentialBody>;
        this.#credentials.set(credential.body.d, credential);
      }
    }

    for (const events of this.#keyEvents.values()) {
      events.sort((a, b) => Number.parseInt(a.body.s, 16) - Number.parseInt(b.body.s, 16));
    }
  }

  /**
   * Key events for `aid`, preceded by those of every delegator above it so
   * `KeyEventLog` can verify a delegated AID's `dip` anchor.
   */
  keyEvents(aid: string): Message<KeyEventBody>[] {
    const chain: Message<KeyEventBody>[] = [];
    const visited = new Set<string>();
    let current: string | undefined = aid;

    while (current !== undefined && !visited.has(current)) {
      visited.add(current);
      const events = this.#keyEvents.get(current);
      if (!events) {
        break;
      }

      chain.push(...events);
      const first = events[0];
      current = first?.body.t === "dip" ? (first.body as DipEventBody).di : undefined;
    }

    return chain;
  }

  transactionEvents(registry: string): Message<TransactionEventBody>[] {
    return this.#transactionEvents.get(registry) ?? [];
  }

  get credentials(): Message<CredentialBody>[] {
    return Array.from(this.#credentials.values());
  }

  credential(said: string): Message<CredentialBody> | null {
    return this.#credentials.get(said) ?? null;
  }

  get identifiers(): string[] {
    return Array.from(this.#keyEvents.keys());
  }

  get registries(): string[] {
    return Array.from(this.#transactionEvents.keys());
  }
}

function push<T>(map: Map<string, T[]>, key: string, value: T): void {
  const existing = map.get(key);
  if (existing) {
    existing.push(value);
  } else {
    map.set(key, [value]);
  }
}

interface Entry {
  message: Message;
  duplicates: Attachments[];
}

/**
 * One message per SAID, in the order first encountered, with IPEX embeds
 * unwrapped.
 *
 * Two copies of the same message are not interchangeable: an ACDC unwrapped
 * from a grant is rejoined with the `SealSourceTriples` naming its issuance,
 * which a bare copy of the same ACDC elsewhere in the stream does not carry,
 * and a key event may arrive with or without its signatures. Attachments from
 * every copy are therefore folded together, so a copy that happens to arrive
 * without them is not what gets indexed.
 */
function flatten(messages: Iterable<Message>): Message[] {
  const entries: Entry[] = [];
  const byDigest = new Map<string, Entry>();

  // Grows as IPEX grants are unwrapped, so embeds are flattened on the same
  // terms as anything that arrived on the stream directly.
  const pending = Array.from(messages);

  for (let i = 0; i < pending.length; i++) {
    const message = pending[i];

    // Unwrapped once per copy rather than once per SAID: a second copy of an
    // exn can carry pathed attachments the first lacked, and the embeds it
    // yields merge by SAID like anything else.
    if (message.body.t === "exn") {
      pending.push(...Object.values(embeds(message as Message<ExchangeEventBody>)));
      continue;
    }

    const digest = message.body.d;
    if (typeof digest !== "string") {
      entries.push({ message, duplicates: [] });
      continue;
    }

    const existing = byDigest.get(digest);
    if (existing) {
      existing.duplicates.push(message.attachments);
      continue;
    }

    const entry: Entry = { message, duplicates: [] };
    entries.push(entry);
    byDigest.set(digest, entry);
  }

  // Rebuilding from the same body reproduces the same raw bytes, since that is
  // how the parser built the message in the first place.
  return entries.map(({ message, duplicates }) =>
    duplicates.length === 0 ? message : new Message(message.body, merge([message.attachments, ...duplicates])),
  );
}

/**
 * Signatures and receipts are unioned; seal hints are taken whole from the
 * first copy that carries any.
 *
 * The two cannot be treated alike. A signature that does not check out is
 * ignored, so pooling them across copies can only help. A seal hint is a
 * conjunct — `findSealAnchor` fails the event unless *every* attached hint
 * resolves — so pooling those only ever adds ways to fail, and one copy naming
 * an anchor that is not in the KEL would invalidate an event another copy
 * anchors correctly. A copy carrying no hint at all still learns one from a
 * copy that does, which is what an ACDC unwrapped from a grant needs.
 */
function merge(copies: Attachments[]): AttachmentsInit {
  return {
    ControllerIdxSigs: unique(copies.flatMap((a) => a.ControllerIdxSigs)),
    WitnessIdxSigs: unique(copies.flatMap((a) => a.WitnessIdxSigs)),
    FirstSeenReplayCouples: unique(copies.flatMap((a) => a.FirstSeenReplayCouples)),
    NonTransReceiptCouples: unique(copies.flatMap((a) => a.NonTransReceiptCouples)),
    TransIdxSigGroups: unique(copies.flatMap((a) => a.TransIdxSigGroups)),
    TransLastIdxSigGroups: unique(copies.flatMap((a) => a.TransLastIdxSigGroups)),
    PathedMaterialCouples: unique(copies.flatMap((a) => a.PathedMaterialCouples)),
    SealSourceTriples: firstPresent(copies, (a) => a.SealSourceTriples),
    SealSourceCouples: firstPresent(copies, (a) => a.SealSourceCouples),
  };
}

function firstPresent<T>(copies: Attachments[], select: (attachments: Attachments) => T[]): T[] {
  return copies.map(select).find((entries) => entries.length > 0) ?? [];
}

// A replayed stream would otherwise double every signature it carries.
function unique<T>(entries: T[]): T[] {
  const seen = new Set<string>();

  return entries.filter((entry) => {
    const key = JSON.stringify(entry);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
