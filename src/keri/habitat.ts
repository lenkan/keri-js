import type { EventStore, KeyEventMessage } from "../db/event-store.ts";
import type { KeyStore } from "../keystore/keystore.ts";
import { cesr, CounterCode } from "../main-common.ts";
import { parse } from "../parser/parser.ts";
import { resolveKeyState, submit } from "./keri.ts";
import type { InteractEvent, ReplyEvent, InceptEvent } from "../events/main.ts";
import { interact, incept } from "../events/main.ts";

export interface HabitatDeps {
  keystore: KeyStore;
  db: EventStore;
}

export interface InceptIdentifierArgs {
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

  async create(args: InceptIdentifierArgs): Promise<InceptEvent> {
    const keys = [await this.#keystore.incept(), await this.#keystore.incept()];
    const toad = args.toad ?? (args.wits.length === 0 ? 0 : args.wits.length === 1 ? 1 : args.wits.length - 1);

    const payload = incept({
      kt: "1",
      k: keys.map((key) => key.current),
      nt: "1",
      n: keys.map((key) => key.next),
      bt: toad.toString(),
      b: args.wits,
    });

    await this.#db.saveEvent(payload);

    const raw = new TextEncoder().encode(JSON.stringify(payload));

    await Promise.all(
      keys.map(async (key, index) => {
        const sig = await this.#keystore.sign(key.current, raw);

        await this.#db.saveAttachment(payload.d, {
          code: CounterCode.ControllerIdxSigs,
          value: cesr.index(sig, index),
        });
      }),
    );

    await this.submit(payload.d);

    return payload;
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
      const response = await submit(
        {
          event: event.event,
          signatures: {
            controllers: event.attachments
              .filter((attachment) => attachment.code === CounterCode.ControllerIdxSigs)
              .map((attachment) => attachment.value),
            witnesses: [],
          },
        },
        wit,
      );

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
