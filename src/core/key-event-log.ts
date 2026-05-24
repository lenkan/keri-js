import { type Attachments, Message, parse } from "../cesr/main.ts";
import type {
  DipEventBody,
  DrtEventBody,
  InceptEventBody,
  InteractEventBody,
  KeyEventBody,
  KeyState,
  RotateEventBody,
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

  static from(events: Iterable<Message<KeyEventBody>>, options?: AppendOptions): KeyEventLog {
    let log = KeyEventLog.empty();
    for (const event of events) {
      log = log.append(event, options);
    }
    return log;
  }

  static async parse(stream: AsyncIterable<Uint8Array>, options?: AppendOptions): Promise<KeyEventLog> {
    const byAid = new Map<string, Message<KeyEventBody>[]>();
    const order: string[] = [];

    for await (const message of parse(stream)) {
      // TODO: Verify that the message is a valid KeyEventBody before casting
      if (!isKelEventType(message.body.t)) {
        continue;
      }
      const m = message as Message<KeyEventBody>;
      const aid = m.body.i;
      let list = byAid.get(aid);
      if (!list) {
        list = [];
        byAid.set(aid, list);
        order.push(aid);
      }
      list.push(m);
    }

    if (byAid.size === 0) {
      return KeyEventLog.empty();
    }
    if (byAid.size === 1) {
      return KeyEventLog.from(byAid.values().next().value as Message<KeyEventBody>[], options);
    }

    // Multi-AID stream: typical OOBI for a delegated AID returns the delegator
    // chain plus the delegate. Pick the leaf (an AID not referenced as `di` by
    // any other AID's dip) and build the chain bottom-up so dip verification
    // sees a complete delegator KEL.
    const referencedAsDelegator = new Set<string>();
    for (const events of byAid.values()) {
      const dip = events.find((e) => e.body.t === "dip");
      if (dip && typeof (dip.body as DipEventBody).di === "string") {
        referencedAsDelegator.add((dip.body as DipEventBody).di);
      }
    }

    const leaves = order.filter((aid) => !referencedAsDelegator.has(aid));
    if (leaves.length === 0) {
      throw new Error("KeyEventLog.parse: no leaf AID in multi-AID stream (cycle?)");
    }
    if (leaves.length > 1) {
      throw new Error(`KeyEventLog.parse: ambiguous multi-AID stream, found ${leaves.length} leaf AIDs`);
    }

    const buildFor = (aid: string): KeyEventLog => {
      const events = byAid.get(aid) ?? [];
      let delegator: KeyEventLog | undefined;
      const first = events[0];
      if (first && first.body.t === "dip") {
        const delegatorAid = (first.body as DipEventBody).di;
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

        const icp = body as InceptEventBody;
        if (!icp.k || !Array.isArray(icp.k) || icp.k.length === 0) {
          throw new Error("Inception event must have at least one key");
        }

        verifySigning(bodyRaw, {
          keys: icp.k,
          threshold: icp.kt as string[] | string,
          sigs,
        });

        if (icp.b && Array.isArray(icp.b) && icp.b.length > 0) {
          verifyWitness(bodyRaw, {
            keys: icp.b,
            threshold: icp.bt as string[] | string,
            sigs: wigs,
          });
        }

        if (body.t === "dip" && delegator) {
          verifyDelegationAnchor(body as DipEventBody, message.attachments, delegator);
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
          verifyDelegationAnchor(body as DrtEventBody, message.attachments, delegator);
        }
        break;
      }
      default:
        throw new Error(`Unsupported event type: ${body.t}`);
    }

    const newState = reduceKeyState(this.#state, body);
    return new KeyEventLog([...this.#events, message], newState, delegator ?? null);
  }
}

function isKelEventType(t: unknown): boolean {
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
  const matchingSeal = (event: Message<KeyEventBody>) => {
    const anchors = (event.body as { a?: KeyEventSeal[] }).a ?? [];
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
    case "icp": {
      const icp = body as InceptEventBody;
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
    case "dip": {
      const dip = body as DipEventBody;
      return {
        identifier: dip.i,
        signingThreshold: dip.kt,
        signingKeys: dip.k,
        nextThreshold: dip.nt,
        nextKeyDigests: dip.n,
        backerThreshold: dip.bt,
        backers: dip.b,
        configTraits: dip.c,
        delegator: dip.di,
        lastEvent: { i: dip.i, s: dip.s, d: dip.d },
        lastEstablishment: { i: dip.i, s: dip.s, d: dip.d },
      };
    }
    case "ixn": {
      assertDefined(state);
      const ixn = body as InteractEventBody;
      return merge(state, { lastEvent: { i: ixn.i, s: ixn.s, d: ixn.d } });
    }
    case "rot":
    case "drt": {
      assertDefined(state);
      const rot = body as RotateEventBody | DrtEventBody;
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
