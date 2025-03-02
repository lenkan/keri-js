import type { EventStore, KeyEventMessage } from "../events/event-store.ts";
import type { KeyStore } from "../keystore/keystore.ts";
import { cesr, CounterCode } from "../main-common.ts";
import { parse } from "../parser/parser.ts";
import { encodeBase64Int } from "../parser/base64.ts";
import { MatterCode } from "../parser/codes.ts";
import { resolveKeyState, submit } from "./keri.ts";
import type { InteractEvent, ReplyEvent, InceptEvent } from "../events/main.ts";
import { interact } from "../events/main.ts";

export interface HabitatDeps {
  keystore: KeyStore;
  db: EventStore;
}

export interface InceptIdentifierArgs {
  keys: string[];
  next?: string[];
  wits: string[];
  toad?: number;
}

export class Habitat {
  #db: EventStore;
  #keystore: KeyStore;

  constructor(deps: HabitatDeps) {
    this.#db = deps.db;
    this.#keystore = deps.keystore;
  }

  async create(event: InceptEvent, signatures: string[]): Promise<void> {
    await this.#db.saveEvent(event);

    await this.#db.saveAttachment(event.d, {
      code: CounterCode.FirstSeenReplayCouples,
      value: ["0A", MatterCode.Salt_128, encodeBase64Int(0, 22), cesr.encodeDate(new Date())].join(""),
    });

    await Promise.all(
      signatures.map(async (sig, index) => {
        await this.#db.saveAttachment(event.d, {
          code: CounterCode.ControllerIdxSigs,
          value: cesr.index(sig, index),
        });
      }),
    );

    await this.submit(event.d);
  }

  async interact(aid: string): Promise<InteractEvent> {
    const events = await this.#db.list({ i: aid });

    if (events.length === 0) {
      throw new Error(`Could not find aid ${aid}`);
    }

    const state = resolveKeyState(events.map((e) => e.event));

    const payload = interact({
      i: aid,
      s: (parseInt(state.s, 16) + 1).toString(),
      a: [],
      p: state.event,
    });

    await this.#db.saveEvent(payload);

    const raw = new TextEncoder().encode(JSON.stringify(payload));

    await Promise.all(
      state.keys.map(async (key, index) => {
        const sig = await this.#keystore.sign(key, raw);

        await this.#db.saveAttachment(payload.d, {
          code: CounterCode.ControllerIdxSigs,
          value: cesr.index(sig, index),
        });
      }),
    );

    await this.submit(payload.d);

    return payload;
  }

  async resolve(oobi: string) {
    const response = await fetch(oobi);
    if (!response.ok) {
      throw new Error(`Failed to fetch oobi: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      throw new Error(`No body in response`);
    }

    for await (const event of parse(response.body)) {
      this.#db.saveEvent(event.payload as InceptEvent);
    }
  }

  async submit(eventId: string) {
    const [event] = await this.#db.list({ d: eventId });

    if (!event || !("i" in event.event && typeof event.event.i === "string")) {
      throw new Error("No such event");
    }

    const [inception] = await this.#db.list({ i: event.event.i, t: "icp" });

    if (!inception) {
      throw new Error("No inception event found");
    }

    const state = resolveKeyState([inception.event]);

    const locations = await this.#db.list({ t: "rpy", r: "/loc/scheme" });

    const witnessEndpoints = await Promise.all(
      state.wits.map((wit) => {
        const result = locations.map((loc) => loc.event as ReplyEvent).find((rpy) => rpy.a.eid === wit);

        if (!result) {
          throw new Error(`No location found for wit ${wit}`);
        }

        return result.a.url as string;
      }),
    );

    for (const wit of witnessEndpoints) {
      const response = await submit(event, wit);

      for await (const receipt of parse(response)) {
        await this.#db.saveEvent(receipt.payload);

        let code: string | null = null;
        for (const attachment of receipt.attachments) {
          if (attachment.startsWith("-")) {
            code = attachment;
          } else if (code) {
            await this.#db.saveAttachment(receipt.payload.d, { code: code, value: attachment });
            code = null;
          }
        }
      }
    }
  }

  async list(id: string): Promise<KeyEventMessage[]> {
    return this.#db.list({ i: id });
  }
}
