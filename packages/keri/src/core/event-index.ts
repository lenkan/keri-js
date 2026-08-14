import type { Message, ParseInput } from "cesr";
import { parse } from "cesr";
import type { CredentialBody } from "./credential.ts";
import type { DipEventBody, KeyEventBody } from "./key-event.ts";
import { isKelEventType } from "./key-event-log.ts";
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
    const seen = new Set<string>();

    for (const message of messages) {
      const digest = message.body.d;

      // A replayed stream would otherwise fail on a duplicate inception event.
      if (typeof digest === "string") {
        if (seen.has(digest)) {
          continue;
        }
        seen.add(digest);
      }

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
      // Everything else, `exn` included, is ignored. Unwrapping IPEX only has to
      // add messages here; nothing downstream changes.
    }

    for (const events of this.#keyEvents.values()) {
      events.sort((a, b) => Number.parseInt(a.body.s, 16) - Number.parseInt(b.body.s, 16));
    }
  }

  static async parse(input: ParseInput): Promise<EventIndex> {
    return new EventIndex(await Array.fromAsync(parse(input)));
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
