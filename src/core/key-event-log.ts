import { type Attachments, Message, type ParseInput, parse } from "../cesr/main.ts";
import { nextKeyDigest } from "./digest.ts";
import type {
  DipEventBody,
  DrtEventBody,
  InceptEventBody,
  InteractEventBody,
  KeyEventBody,
  KeyState,
  RotateEventBody,
} from "./key-event.ts";
import { isEstablishment, isKelEventType } from "./key-event.ts";
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

  static from(events: Iterable<Message<KeyEventBody>>, options?: AppendOptions): KeyEventLog {
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
  static async parse(stream: ParseInput, options?: AppendOptions): Promise<KeyEventLog> {
    const messages: Message<KeyEventBody>[] = [];
    for await (const message of parse(stream)) {
      // TODO: Verify that the message is a valid KeyEventBody before casting
      if (isKelEventType(message.body.t)) {
        messages.push(message as Message<KeyEventBody>);
      }
    }
    return KeyEventLog.fromMessages(messages, options);
  }

  /**
   * Same multi-AID handling as `parse`, but operates on pre-collected
   * messages — useful when the caller has already consumed the stream
   * (e.g. to split KEL events from `rpy` messages in the same response).
   */
  static fromMessages(messages: Iterable<Message<KeyEventBody>>, options?: AppendOptions): KeyEventLog {
    const byAid = new Map<string, Message<KeyEventBody>[]>();
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
      return KeyEventLog.from(byAid.values().next().value as Message<KeyEventBody>[], options);
    }

    const referencedAsDelegator = new Set<string>();
    for (const events of byAid.values()) {
      const dip = events.find((e) => e.body.t === "dip");
      if (dip && typeof (dip.body as DipEventBody).di === "string") {
        referencedAsDelegator.add((dip.body as DipEventBody).di);
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
          threshold: icp.kt,
          sigs,
        });

        // A zero backer threshold is valid KERI — witnesses listed, no
        // receipts required — and must not reach the threshold parser, which
        // (correctly) rejects 0 for signing thresholds.
        if (icp.b && Array.isArray(icp.b) && icp.b.length > 0 && !isZeroThreshold(icp.bt)) {
          verifyWitness(bodyRaw, {
            keys: icp.b,
            threshold: icp.bt,
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

        if (isEstablishment(body.t)) {
          // Each newly exposed key must have been pre-committed as a digest in
          // the prior establishment event. Reserve/partial rotations, where `k`
          // keeps unexposed extras, are not supported.
          const rot = body as RotateEventBody | DrtEventBody;
          for (const key of rot.k) {
            if (!state.nextKeyDigests.includes(nextKeyDigest(key))) {
              throw new Error(`Rotation key ${key} was not committed by the prior establishment event`);
            }
          }

          verifySigning(bodyRaw, { keys: rot.k, threshold: rot.kt, sigs });
        } else {
          verifySigning(bodyRaw, {
            keys: state.signingKeys,
            threshold: state.signingThreshold as string[] | string,
            sigs,
          });
        }

        if (state.backers && state.backers.length > 0 && !isZeroThreshold(state.backerThreshold as string)) {
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

interface KeyEventSeal {
  i?: string;
  s?: string;
  d?: string;
}

/** The `i`/`s`/`d` triple a seal in an anchoring event's `a` field must match. */
export interface AnchorTarget {
  i: string;
  s: string;
  d: string;
}

/** Why no anchoring event was accepted. Callers phrase their own error from it. */
export type SealAnchorFailure =
  | { kind: "hint-missing"; snu: string; digest: string }
  | { kind: "hint-unanchored"; digest: string }
  | { kind: "unanchored" };

/**
 * Find the event in `anchoring` whose `a` field carries a seal for `target`,
 * returning null on success.
 *
 * A SealSourceCouple/Triple, when attached, names the anchoring event directly,
 * and every attached one must resolve. keripy does not always transmit it, so
 * with no hint the whole log is scanned instead.
 *
 * Shared by delegation (`dip`/`drt`) and registry (`vcp`/`iss`/`rev`) anchoring,
 * which differ only in how they report failure.
 */
export function findSealAnchor(
  target: AnchorTarget,
  attachments: Attachments,
  anchoring: { identifier: string; events: Message<KeyEventBody>[] },
): SealAnchorFailure | null {
  const hints = [
    ...attachments.SealSourceCouples.map((c) => ({ snu: c.snu, digest: c.digest })),
    ...attachments.SealSourceTriples.filter((t) => t.prefix === anchoring.identifier).map((t) => ({
      snu: t.snu,
      digest: t.digest,
    })),
  ];

  const anchors = (event: Message<KeyEventBody>) => {
    const seals = (event.body as { a?: KeyEventSeal[] }).a ?? [];
    return seals.some((seal) => seal.i === target.i && seal.s === target.s && seal.d === target.d);
  };

  if (hints.length === 0) {
    return anchoring.events.some(anchors) ? null : { kind: "unanchored" };
  }

  for (const hint of hints) {
    const event = anchoring.events.find((e) => e.body.d === hint.digest && e.body.s === hint.snu);
    if (!event) {
      return { kind: "hint-missing", snu: hint.snu, digest: hint.digest };
    }
    if (!anchors(event)) {
      return { kind: "hint-unanchored", digest: hint.digest };
    }
  }

  return null;
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

  const failure = findSealAnchor(body, attachments, {
    identifier: delegator.state.identifier,
    events: delegator.events,
  });

  switch (failure?.kind) {
    case "hint-missing":
      throw new Error(`Delegator anchor not found in KEL: s=${failure.snu} d=${failure.digest} (delegator=${body.di})`);
    case "hint-unanchored":
      throw new Error(
        `Delegator event ${failure.digest} does not anchor ${body.t} ${body.d}: missing matching key-event seal in a[]`,
      );
    case "unanchored":
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

function isZeroThreshold(threshold: string | string[] | undefined): boolean {
  return typeof threshold === "string" && Number.parseInt(threshold || "0", 16) === 0;
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
