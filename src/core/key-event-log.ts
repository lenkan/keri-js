import { type Attachments, Message, parse } from "../cesr/main.ts";
import {
  type DipEventBody,
  type DrtEventBody,
  type InceptEventBody,
  type InteractEventBody,
  isKeyEvent,
  type KeyEvent,
  type KeyEventBody,
  type KeyState,
  type RotateEventBody,
} from "./key-event.ts";
import { verifySignaturesOrThrow, verifyThresholdOrThrow } from "./verify.ts";

export interface AppendOptions {
  /** Allow appending an event whose controller signatures don't meet the signing threshold. Individual signatures that are present must still be cryptographically valid. */
  allowPartiallySigned?: boolean;
  /** Allow appending an event whose witness signatures don't meet the backer threshold. Individual signatures that are present must still be cryptographically valid. */
  allowPartiallyWitnessed?: boolean;
  /**
   * KEL of the delegator. When provided and the appended event is a `dip` or
   * `drt`, the SealSourceCouple/Triple in the event's attachments is verified
   * against the delegator's KEL — proving the delegator anchored this event
   * via an `ixn` whose `a` field carries a matching key-event seal. The
   * returned KEL retains the delegator so subsequent `ixn`/`rot`/`drt` appends
   * carry the same verified anchor chain.
   *
   * Omitting this option for a delegated event is a deliberate "skip
   * delegator-anchor verification" choice. Callers that load delegated KELs
   * from storage (`KeyEventLog.from(storage.getKeyEvents(...))`) without
   * re-supplying the delegator KEL will not re-verify the anchor at load time.
   *
   * When both `SealSourceCouples` and `SealSourceTriples` are attached, every
   * referenced entry must validate — any single broken hint fails the append.
   */
  delegator?: KeyEventLog;
}

export type {
  InceptEventBody as InceptEvent,
  InteractEventBody as InteractEvent,
  KeyState,
  RotateEventBody as RotateEvent,
};

export class KeyEventLog {
  #events: Message<KeyEventBody>[];
  #state: KeyState | null;
  #delegator: KeyEventLog | null;

  private constructor(events: Message<KeyEventBody>[], state: KeyState | null, delegator: KeyEventLog | null = null) {
    this.#events = events;
    this.#state = state;
    this.#delegator = delegator;
  }

  static empty(): KeyEventLog {
    return new KeyEventLog([], null);
  }

  static from(events: Iterable<KeyEvent>, options?: AppendOptions): KeyEventLog {
    let log = KeyEventLog.empty();
    for (const event of events) {
      log = log.append(event, options);
    }
    return log;
  }

  /**
   * Parse a CESR byte stream of KEL events into a verified KeyEventLog.
   *
   * Non-KEL messages in the stream are ignored. For multi-AID streams (e.g.
   * an OOBI response for a delegated AID that returns both the delegator's
   * KEL and the delegate's), the leaf AID — one not referenced as `di` by
   * any other dip — is selected and the delegator chain is built bottom-up
   * so the dip's anchor can be verified against the delegator's KEL.
   *
   * Throws on a multi-AID stream that has no leaf (cycle) or more than one
   * leaf (ambiguous — e.g. two unrelated AIDs).
   */
  static async parse(stream: AsyncIterable<Uint8Array>, options?: AppendOptions): Promise<KeyEventLog> {
    const messages: KeyEvent[] = [];
    for await (const message of parse(stream)) {
      // Shallow guard: matches on `t`. Structural + SAID validation is done later in append().
      if (isKeyEvent(message)) {
        messages.push(message);
      }
    }
    return KeyEventLog.fromMessages(messages, options);
  }

  /**
   * Same multi-AID handling as `parse`, but operates on pre-collected
   * messages — useful when the caller has already consumed the stream
   * (e.g. to split KEL events from `rpy` messages in the same response).
   */
  static fromMessages(messages: Iterable<KeyEvent>, options?: AppendOptions): KeyEventLog {
    const byAid = new Map<string, KeyEvent[]>();
    for (const m of messages) {
      let list = byAid.get(m.body.i);
      if (!list) {
        list = [];
        byAid.set(m.body.i, list);
      }
      list.push(m);
    }

    if (byAid.size === 0) {
      return KeyEventLog.empty();
    }
    if (byAid.size === 1) {
      return KeyEventLog.from(byAid.values().next().value as KeyEvent[], options);
    }

    const referencedAsDelegator = new Set<string>();
    for (const events of byAid.values()) {
      const dip = events.find((e) => e.body.t === "dip");
      if (dip && dip.body.t === "dip") {
        referencedAsDelegator.add(dip.body.di);
      }
    }

    const leaves = Array.from(byAid.keys()).filter((aid) => !referencedAsDelegator.has(aid));
    if (leaves.length === 0) {
      throw new Error("KeyEventLog.fromMessages: no leaf AID in multi-AID stream (cycle?)");
    }
    if (leaves.length > 1) {
      throw new Error(`KeyEventLog.fromMessages: ambiguous multi-AID stream, found ${leaves.length} leaf AIDs`);
    }

    const buildFor = (aid: string): KeyEventLog => {
      const events = byAid.get(aid) ?? [];
      let delegator: KeyEventLog | undefined;
      const first = events[0];
      if (first && first.body.t === "dip") {
        const delegatorAid = first.body.di;
        if (byAid.has(delegatorAid)) {
          delegator = buildFor(delegatorAid);
        }
      }
      return KeyEventLog.from(events, { ...options, delegator });
    };

    return buildFor(leaves[0]);
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

  /** The delegator's KEL when this KEL belongs to a delegated AID and was constructed with one; null otherwise. */
  get delegator(): KeyEventLog | null {
    return this.#delegator;
  }

  append(message: Message<KeyEventBody>, options?: AppendOptions): KeyEventLog {
    const sigs = message.attachments.ControllerIdxSigs ?? [];
    const wigs = message.attachments.WitnessIdxSigs ?? [];
    const body = message.body;
    const bodyRaw = new Message(body).raw;

    const verifySigning = options?.allowPartiallySigned ? verifySignaturesOrThrow : verifyThresholdOrThrow;
    const verifyWitness = options?.allowPartiallyWitnessed ? verifySignaturesOrThrow : verifyThresholdOrThrow;
    const delegator = options?.delegator ?? this.#delegator;

    switch (body.t) {
      case "icp":
      case "dip": {
        if (this.#state !== null) {
          throw new Error("State already initialized");
        }

        if (!body.k || !Array.isArray(body.k) || body.k.length === 0) {
          throw new Error("Inception event must have at least one key");
        }

        verifySigning(bodyRaw, {
          keys: body.k,
          threshold: body.kt,
          sigs,
        });

        if (body.b && Array.isArray(body.b) && body.b.length > 0) {
          verifyWitness(bodyRaw, {
            keys: body.b,
            threshold: body.bt,
            sigs: wigs,
          });
        }

        if (body.t === "dip" && delegator) {
          verifyDelegationAnchor(body, message.attachments, delegator);
        }
        break;
      }
      case "ixn":
      case "rot":
      case "drt": {
        if (this.#state === null) {
          throw new Error("State must be initialized before applying interact or rotate events");
        }

        const state = this.#state;
        verifySigning(bodyRaw, {
          keys: state.signingKeys,
          threshold: state.signingThreshold as string[] | string,
          sigs,
        });
        if (state.backers && state.backers.length > 0) {
          verifyWitness(bodyRaw, {
            keys: state.backers,
            threshold: state.backerThreshold as string[] | string,
            sigs: wigs,
          });
        }

        if (body.t === "drt" && delegator) {
          verifyDelegationAnchor(body, message.attachments, delegator);
        }
        break;
      }
    }

    const newState = reduceKeyState(this.#state, body);
    return new KeyEventLog([...this.#events, message], newState, delegator ?? null);
  }
}

export function isKelEventType(t: unknown): boolean {
  return t === "icp" || t === "ixn" || t === "rot" || t === "dip" || t === "drt";
}

interface KeyEventSeal {
  i?: string;
  s?: string;
  d?: string;
}

function verifyDelegationAnchor(
  body: DipEventBody | DrtEventBody,
  attachments: Attachments,
  delegator: KeyEventLog,
): void {
  if (body.di !== delegator.state.identifier) {
    throw new Error(
      `Delegation mismatch: event di=${body.di} does not match delegator KEL identifier=${delegator.state.identifier}`,
    );
  }

  const couples = attachments.SealSourceCouples ?? [];
  const triples = attachments.SealSourceTriples ?? [];
  const hints = [
    ...couples.map((c) => ({ snu: c.snu, digest: c.digest })),
    ...triples.filter((t) => t.prefix === body.di).map((t) => ({ snu: t.snu, digest: t.digest })),
  ];

  // If a SealSourceCouple/Triple is attached, use it as a hint about which
  // delegator event carries the anchor. Otherwise scan the delegator's KEL
  // for any event whose `a` field anchors this dip/drt — keripy's wire
  // format relies on the verifier deriving the anchor from the delegator's
  // KEL directly when the couple isn't transmitted.
  const matchingSeal = (event: KeyEvent) => {
    const anchors = (event.body.a ?? []) as KeyEventSeal[];
    return anchors.some((seal) => seal.i === body.i && seal.s === body.s && seal.d === body.d);
  };

  if (hints.length > 0) {
    for (const ref of hints) {
      const event = delegator.events.find((e) => e.body.d === ref.digest && e.body.s === ref.snu);
      if (!event) {
        throw new Error(`Delegator anchor not found in KEL: s=${ref.snu} d=${ref.digest} (delegator=${body.di})`);
      }
      if (!matchingSeal(event)) {
        throw new Error(
          `Delegator event ${ref.digest} does not anchor ${body.t} ${body.d}: missing matching key-event seal in a[]`,
        );
      }
    }
    return;
  }

  const anchorEvent = delegator.events.find((e) => matchingSeal(e));
  if (!anchorEvent) {
    throw new Error(`No anchoring event found in delegator KEL for ${body.t} ${body.d} (delegator=${body.di})`);
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
    delegator: b.delegator ?? a.delegator,
    lastEvent: b.lastEvent ?? a.lastEvent,
    lastEstablishment: b.lastEstablishment ?? a.lastEstablishment,
  };
}

function reduceKeyState(state: KeyState | null, body: KeyEventBody): KeyState {
  switch (body.t) {
    case "icp":
      return {
        identifier: body.i,
        signingThreshold: body.kt,
        signingKeys: body.k,
        nextThreshold: body.nt,
        nextKeyDigests: body.n,
        backerThreshold: body.bt,
        backers: body.b,
        configTraits: body.c,
        lastEvent: { i: body.i, s: body.s, d: body.d },
        lastEstablishment: { i: body.i, s: body.s, d: body.d },
      };
    case "dip":
      return {
        identifier: body.i,
        signingThreshold: body.kt,
        signingKeys: body.k,
        nextThreshold: body.nt,
        nextKeyDigests: body.n,
        backerThreshold: body.bt,
        backers: body.b,
        configTraits: body.c,
        delegator: body.di,
        lastEvent: { i: body.i, s: body.s, d: body.d },
        lastEstablishment: { i: body.i, s: body.s, d: body.d },
      };
    case "ixn":
      assertDefined(state);
      return merge(state, { lastEvent: { i: body.i, s: body.s, d: body.d } });
    case "rot":
    case "drt":
      assertDefined(state);
      return merge(state, {
        backers: state.backers.filter((b) => !body.br.includes(b)).concat(body.ba),
        backerThreshold: body.bt,
        signingKeys: body.k,
        signingThreshold: body.kt,
        nextKeyDigests: body.n,
        nextThreshold: body.nt,
        lastEvent: { i: body.i, s: body.s, d: body.d },
        lastEstablishment: { i: body.i, s: body.s, d: body.d },
      });
  }
}
