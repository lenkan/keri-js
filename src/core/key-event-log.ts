import { Message, parse } from "../cesr/__main__.ts";
import type { InceptEvent, InteractEvent, KeyEventBody, KeyState, RotateEvent } from "./key-event.ts";
import { verifyOrThrow } from "./verify.ts";

export type { InceptEvent, InteractEvent, KeyState, RotateEvent };

export class KeyEventLog {
  #events: Message<KeyEventBody>[];
  #state: KeyState | null;

  private constructor(events: Message<KeyEventBody>[], state: KeyState | null) {
    this.#events = events;
    this.#state = state;
  }

  static empty(): KeyEventLog {
    return new KeyEventLog([], null);
  }

  static from(events: Iterable<Message<KeyEventBody>>): KeyEventLog {
    let log = KeyEventLog.empty();
    for (const event of events) {
      log = log.append(event);
    }
    return log;
  }

  static async parse(stream: AsyncIterable<Uint8Array>): Promise<KeyEventLog> {
    let log = KeyEventLog.empty();

    for await (const message of parse(stream)) {
      // TODO: Verify that the message is a valid KeyEventBody before casting
      if (message.body.t === "icp" || message.body.t === "ixn" || message.body.t === "rot") {
        log = log.append(message as Message<KeyEventBody>);
      }
    }

    return log;
  }

  get state(): KeyState {
    if (this.#state === null) {
      throw new Error("No events in KEL");
    }
    return this.#state;
  }

  get events(): Message<KeyEventBody>[] {
    return this.#events;
  }

  append(message: Message<KeyEventBody>): KeyEventLog {
    const sigs = message.attachments.ControllerIdxSigs ?? [];
    const wigs = message.attachments.WitnessIdxSigs ?? [];
    const body = message.body;
    const bodyRaw = new Message(body).raw;

    switch (body.t) {
      case "icp": {
        if (this.#state !== null) {
          throw new Error("State already initialized");
        }

        const icp = body as InceptEvent;
        if (!icp.k || !Array.isArray(icp.k) || icp.k.length === 0) {
          throw new Error("Inception event must have at least one key");
        }

        verifyOrThrow(bodyRaw, {
          keys: icp.k,
          threshold: icp.kt as string[] | string,
          sigs,
        });

        if (icp.b && Array.isArray(icp.b) && icp.b.length > 0) {
          verifyOrThrow(bodyRaw, {
            keys: icp.b,
            threshold: icp.bt as string[] | string,
            sigs: wigs,
          });
        }
        break;
      }
      case "ixn":
      case "rot": {
        if (this.#state === null) {
          throw new Error("State must be initialized before applying interact or rotate events");
        }

        const state = this.#state;
        verifyOrThrow(bodyRaw, {
          keys: state.signingKeys,
          threshold: state.signingThreshold as string[] | string,
          sigs,
        });
        if (state.backers && state.backers.length > 0) {
          verifyOrThrow(bodyRaw, {
            keys: state.backers,
            threshold: state.backerThreshold as string[] | string,
            sigs: wigs,
          });
        }
        break;
      }
      default:
        throw new Error(`Unsupported event type: ${body.t}`);
    }

    const newState = reduceKeyState(this.#state, body);
    return new KeyEventLog([...this.#events, message], newState);
  }
}

function assertDefined<T>(obj: T | null): asserts obj is T {
  if (obj === null) {
    throw new Error("Object is null");
  }
}

function merge(a: KeyState, b: Partial<KeyState>): KeyState {
  return {
    identifier: b.identifier ?? a.identifier,
    signingThreshold: b.signingThreshold ?? a.signingThreshold,
    signingKeys: b.signingKeys ?? a.signingKeys,
    nextThreshold: b.nextThreshold ?? a.nextThreshold,
    nextKeyDigests: b.nextKeyDigests ?? a.nextKeyDigests,
    backerThreshold: b.backerThreshold ?? a.backerThreshold,
    backers: b.backers ?? a.backers,
    configTraits: b.configTraits ?? a.configTraits,
    lastEvent: b.lastEvent ?? a.lastEvent,
    lastEstablishment: b.lastEstablishment ?? a.lastEstablishment,
  };
}

function reduceKeyState(state: KeyState | null, body: KeyEventBody): KeyState {
  switch (body.t) {
    case "icp": {
      const icp = body as InceptEvent;
      return {
        identifier: icp.i,
        signingThreshold: icp.kt,
        signingKeys: icp.k,
        nextThreshold: icp.nt,
        nextKeyDigests: icp.n,
        backerThreshold: icp.bt,
        backers: icp.b,
        configTraits: icp.c,
        lastEvent: { i: icp.i, s: icp.s, d: icp.d },
        lastEstablishment: { i: icp.i, s: icp.s, d: icp.d },
      };
    }
    case "ixn": {
      assertDefined(state);
      const ixn = body as InteractEvent;
      return merge(state, { lastEvent: { i: ixn.i, s: ixn.s, d: ixn.d } });
    }
    case "rot": {
      assertDefined(state);
      const rot = body as RotateEvent;
      return merge(state, {
        backers: state.backers.filter((b) => !rot.br.includes(b)).concat(rot.ba),
        backerThreshold: rot.bt,
        signingKeys: rot.k,
        signingThreshold: rot.kt,
        nextKeyDigests: rot.n,
        nextThreshold: rot.nt,
        lastEvent: { i: rot.i, s: rot.s, d: rot.d },
        lastEstablishment: { i: rot.i, s: rot.s, d: rot.d },
      });
    }
    default:
      throw new Error(`Unsupported event type: ${body.t}`);
  }
}
