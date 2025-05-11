import {
  formatDate,
  type KeyEvent,
  type DelegatedInceptEvent,
  type InceptEvent,
  type InteractEvent,
  type Threshold,
} from "./events.ts";

export interface KeyEventMessageInput<T extends KeyEvent = KeyEvent> {
  event: T;
  seal?: KeyEventSeal;
  signatures?: string[];
  receipts?: KeyEventReceipt[];
}

export interface KeyEventMessage<T extends KeyEvent = KeyEvent> extends KeyEventMessageInput<T> {
  timestamp: Date;
  signatures: string[];
  receipts: KeyEventReceipt[];
}

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

  async save(event: KeyEventMessageInput) {
    switch (event.event.t) {
      case "icp":
      case "ixn":
      case "iss":
      case "vcp":
      case "rot": {
        if (!event.event.s) {
          throw new Error(`Event sequence number (s) is required for key event ${event.event.t}(${event.event.d})`);
        }

        const sn = event.event.s.padStart(24, "0");
        await this.#db.set(
          `key_event.${event.event.d}`,
          JSON.stringify({
            event: event.event,
            timestamp: new Date().toISOString(),
            seal: event.seal || null,
            sigs: event.signatures || [],
          }),
        );

        await this.#db.set(`key_event_log.${event.event.i}.${sn}`, event.event.d);
        break;
      }
      case "rct": {
        await this.#db.set(`key_event_receipts.${event.event.d}`, JSON.stringify(event.receipts));
        break;
      }
      case "rpy":
        switch (event.event.r) {
          case "/end/role/add": {
            const record = event.event.a;
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
            const record = event.event.a;
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

    if (event.event.v.startsWith("ACDC")) {
      await this.#db.set(
        `key_event.${event.event.d}`,
        JSON.stringify({
          event: event.event,
          timestamp: new Date().toISOString(),
          seal: event.seal || null,
        }),
      );
    }
  }

  async *iter(said: string, from = 0): AsyncIterable<KeyEventMessage> {
    for (let start = from; start < Number.MAX_SAFE_INTEGER; start++) {
      const digest = await this.#db.get(`key_event_log.${said}.${start.toString(16).padStart(24, "0")}`);

      if (digest) {
        const result = await this.get(digest);
        assertKeyEvent(result?.event);
        yield result;
      } else {
        return;
      }
    }
  }

  async get(said: string): Promise<KeyEventMessage | null> {
    const item = JSON.parse((await this.#db.get(`key_event.${said}`)) ?? JSON.stringify(null));
    if (!item) {
      return null;
    }

    assertKeyEvent(item.event);

    const receipts = JSON.parse((await this.#db.get(`key_event_receipts.${said}`)) ?? "[]");

    return {
      event: item.event,
      signatures: item.sigs as string[],
      receipts: receipts as unknown as KeyEventReceipt[],
      timestamp: new Date(Date.parse(item.timestamp)),
      seal: item.seal,
    };
  }

  async state(said: string): Promise<KeyState> {
    let state: KeyState = INITIAL_STATE;

    for await (const message of this.iter(said)) {
      state = reduce(state, message);
    }

    return state;
  }

  async list(said: string, from = 0): Promise<KeyEventMessage[]> {
    const messages: KeyEventMessage[] = [];

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
  event: Iterable<KeyEventMessage> | AsyncIterable<KeyEventMessage>,
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

function reduce(state: KeyState, message: KeyEventMessage): KeyState {
  if (!message.event.v.startsWith("KERI")) {
    return state;
  }

  switch (message.event.t) {
    case "icp":
    case "dip": {
      const icp = message.event as InceptEvent | DelegatedInceptEvent;

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
      const ixn = message.event as InteractEvent;

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
      throw new Error(`Unsupported event type: ${message.event.t}`);
  }
}
