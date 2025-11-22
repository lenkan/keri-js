import { Message } from "cesr";
import {
  formatDate,
  type KeyEvent,
  type DelegatedInceptEvent,
  type InceptEvent,
  type InteractEvent,
  type Threshold,
} from "./events.ts";

export interface LocationRecord {
  url: string;
  scheme: string;
  eid: string;
}

export interface EndRoleRecord {
  cid: string;
  role: string;
  eid: string;
}

export interface KeyEventSeal {
  i: string;
  s: string;
  d: string;
}

export interface KeyEventReceipt {
  backer: string;
  signature: string;
}

export interface KeyValueStorage {
  set(key: string, value: string): Promise<void>;
  get(key: string): Promise<string | null>;
}

function assertKeyEvent(event: unknown): asserts event is KeyEvent {
  if (typeof event !== "object") {
    throw new Error(`Expected event to be an object. Got ${typeof event}`);
  }
}

export class ControllerEventStore {
  #db: KeyValueStorage;

  constructor(db: KeyValueStorage) {
    this.#db = db;
  }

  async save(event: Message<KeyEvent>) {
    switch (event.body.t) {
      case "icp":
      case "ixn":
      case "iss":
      case "vcp":
      case "rot": {
        if (!event.body.s) {
          throw new Error(`Event sequence number (s) is required for key event ${event.body.t}(${event.body.d})`);
        }

        const sn = event.body.s.padStart(24, "0");
        await this.#db.set(
          `key_event.${event.body.d}`,
          JSON.stringify({
            event: event.body,
            timestamp: new Date().toISOString(),
            attachments: {
              ControllerIdxSigs: event.attachments.ControllerIdxSigs || [],
              WitnessIdxSigs: event.attachments.WitnessIdxSigs || [],
              NonTransReceiptCouples: event.attachments.NonTransReceiptCouples || [],
              SealSourceCouples: event.attachments.SealSourceCouples || [],
              SealSourceTriples: event.attachments.SealSourceTriples || [],
            },
          }),
        );

        await this.#db.set(`key_event_log.${event.body.i}.${sn}`, event.body.d);
        break;
      }
      case "rct": {
        await this.#db.set(
          `key_event_receipts.${event.body.d}`,
          JSON.stringify(event.attachments.NonTransReceiptCouples || []),
        );
        break;
      }
      case "rpy":
        switch (event.body.r) {
          case "/end/role/add": {
            const record = event.body.a;
            if (
              record &&
              typeof record === "object" &&
              "eid" in record &&
              typeof record.eid === "string" &&
              "cid" in record &&
              typeof record.cid === "string" &&
              "role" in record &&
              typeof record.role === "string"
            ) {
              await this.#db.set(
                `end_role.${record.cid}.${record.role}`,
                JSON.stringify({
                  cid: record.cid,
                  role: record.role,
                  eid: record.eid,
                }),
              );
            } else {
              throw new Error("Damn");
            }

            break;
          }
          case "/loc/scheme": {
            const record = event.body.a;
            if (
              record &&
              typeof record === "object" &&
              "eid" in record &&
              typeof record.eid === "string" &&
              "scheme" in record &&
              typeof record.scheme === "string" &&
              "url" in record &&
              typeof record.url === "string" &&
              ["http", "https"].includes(record.scheme)
            ) {
              await this.#db.set(
                `location.${record.eid}`,
                JSON.stringify({
                  scheme: record.scheme,
                  url: record.url,
                  eid: record.eid,
                }),
              );
            }
            break;
          }
        }
    }

    if (event.body.v.startsWith("ACDC")) {
      await this.#db.set(
        `key_event.${event.body.d}`,
        JSON.stringify({
          event: event.body,
          timestamp: new Date().toISOString(),
          attachments: {
            SealSourceCouples: event.attachments.SealSourceCouples || [],
            SealSourceTriples: event.attachments.SealSourceTriples || [],
          },
        }),
      );
    }
  }

  async *iter(said: string, from = 0): AsyncIterable<Message<KeyEvent>> {
    for (let start = from; start < Number.MAX_SAFE_INTEGER; start++) {
      const digest = await this.#db.get(`key_event_log.${said}.${start.toString(16).padStart(24, "0")}`);

      if (digest) {
        const result = await this.get(digest);
        assertKeyEvent(result?.body);
        yield result as Message<KeyEvent>;
      } else {
        return;
      }
    }
  }

  async get(said: string): Promise<Message<KeyEvent> | null> {
    const item = JSON.parse((await this.#db.get(`key_event.${said}`)) ?? JSON.stringify(null));
    if (!item) {
      return null;
    }

    assertKeyEvent(item.event);

    return new Message(item.event, {
      ...item.attachments,
      FirstSeenReplayCouples: ["icp", "ixn", "rot"].includes(item.event.t)
        ? [
            {
              fnu: item.event.s,
              dt: new Date(item.timestamp),
            },
          ]
        : [],
    });
  }

  async state(said: string): Promise<KeyState> {
    let state: KeyState = INITIAL_STATE;

    for await (const message of this.iter(said)) {
      state = reduce(state, message);
    }

    return state;
  }

  async list(said: string, from = 0): Promise<Message<KeyEvent>[]> {
    const messages: Message<KeyEvent>[] = [];

    for await (const message of this.iter(said, from)) {
      messages.push(message);
    }

    return messages;
  }

  async location(cid: string): Promise<LocationRecord | null> {
    const result = JSON.parse((await this.#db.get(`location.${cid}`)) ?? JSON.stringify(null));
    return result;
  }

  async endrole(cid: string, role: string): Promise<EndRoleRecord | null> {
    const result = JSON.parse((await this.#db.get(`end_role.${cid}.${role}`)) ?? JSON.stringify(null));
    return result;
  }
}

function assertDefined<T>(obj: T | null): asserts obj is T {
  if (obj === null) {
    throw new Error("Object is null");
  }
}

export interface KeyState {
  vn: [number, number];

  /**
   * Key state identifier
   */
  i: string;

  /**
   * Sequence number of latest event in Key Event Log
   */
  s: string;

  /**
   * Digest of prior event
   */
  p: string;

  /**
   * Digest of latest event
   */
  d: string;

  /**
   * Ordinal number of latest event in KEL
   */
  f: string;

  /**
   * Datetime iso-8601 of when this key state was derived
   */
  dt: string;

  /**
   * Type of latest event
   */
  et: string;

  /**
   * Current key state threshold
   */
  kt: Threshold;

  /**
   * Current signing keys
   */
  k: string[];

  /**
   * Next key state threshold
   */
  nt: Threshold;

  /**
   * Digests of next signing keys
   */
  n: string[];

  /**
   * Backer threshold
   */
  bt: string;

  /**
   * Backers
   */
  b: string[];

  c: string[];

  /**
   * Latest establishment event
   */
  ee: KeyStateEstablishmentRecord;
  di: string;
}

export interface KeyStateEstablishmentRecord {
  /**
   * Sequence number of latest establishment event
   */
  s: string;

  /**
   * Digest of latest establishment event
   */
  d: string;

  /**
   * Backers removed in latest establishment event
   */
  br: string[];

  /**
   * Backers added in latest establishment event
   */
  ba: string[];
}

function merge(a: KeyState, b: Partial<KeyState>): KeyState {
  return {
    vn: [1, 0],
    i: b.i ?? a.i,
    s: b.s ?? a.s,
    p: b.p ?? a.p,
    d: b.d ?? a.d,
    f: b.f ?? a.f,
    dt: b.dt ?? a.dt ?? formatDate(new Date()),
    et: b.et ?? a.et,
    kt: b.kt ?? a.kt,
    k: b.k ?? a.k,
    nt: b.nt ?? a.nt,
    n: b.n ?? a.n,
    bt: b.bt ?? a.bt,
    b: b.b ?? a.b,
    c: b.c ?? a.c,
    ee: b.ee ?? a.ee,
    di: b.di ?? a.di,
  };
}

export async function resolveKeyState(
  event: Iterable<Message<KeyEvent>> | AsyncIterable<Message<KeyEvent>>,
): Promise<KeyState> {
  let state: KeyState = INITIAL_STATE;

  for await (const message of event) {
    state = reduce(state, message);
  }

  return state;
}

const INITIAL_STATE: KeyState = {
  vn: [1, 0],
  i: "",
  s: "",
  p: "",
  d: "",
  f: "0",
  dt: formatDate(new Date()),
  et: "",
  kt: "0",
  k: [],
  nt: "0",
  n: [],
  bt: "",
  b: [],
  c: [],
  ee: { s: "", d: "", br: [], ba: [] },
  di: "",
};

function reduce(state: KeyState, message: Message<KeyEvent>): KeyState {
  if (!message.body.v.startsWith("KERI")) {
    return state;
  }

  switch (message.body.t) {
    case "icp":
    case "dip": {
      const icp = message.body as InceptEvent | DelegatedInceptEvent;

      return {
        vn: [1, 0],
        i: icp.i,
        s: icp.s,
        p: "",
        d: icp.d,
        f: "0",
        dt: formatDate(new Date()),
        et: icp.t,
        kt: icp.kt,
        k: icp.k,
        nt: icp.nt,
        n: icp.n,
        bt: icp.bt,
        b: icp.b,
        c: icp.c,
        ee: {
          s: icp.s,
          d: icp.d,
          br: [],
          ba: icp.b,
        },
        di: "di" in icp && typeof icp.di === "string" ? icp.di : "",
      };
    }
    case "ixn": {
      assertDefined(state);
      const ixn = message.body as InteractEvent;

      if (!state.d) {
        throw new Error("state.d is undefined");
      }

      return merge(state, {
        p: state.d,
        s: ixn.s,
        d: ixn.d,
        et: ixn.t,
        dt: formatDate(new Date()),
      });
    }
    default:
      throw new Error(`Unsupported event type: ${message.body.t}`);
  }
}
