import { Message, type SealSourceCouple } from "../cesr/main.ts";
import { DUMMY_VERSION, encodeEvent } from "../events/main.ts";
import { isTransferable, type Threshold } from "../keys/main.ts";

export interface KeyState {
  identifier: string;
  signingThreshold: Threshold;
  signingKeys: string[];
  nextThreshold: Threshold;
  nextKeyDigests: string[];
  backerThreshold: string;
  backers: string[];
  configTraits: string[];
  delegator?: string;
  lastEvent: {
    i: string;
    s: string;
    d: string;
  };
  lastEstablishment: {
    i: string;
    s: string;
    d: string;
  };
}

export interface InceptArgs {
  signingKeys: string[];
  signingThreshold?: Threshold;
  /** Digests of the next keys, not the keys themselves — see {@link nextKeyDigest}. */
  nextKeyDigests: string[];
  nextThreshold?: Threshold;
  backers?: string[];
  backerThreshold?: number;
  /** Configuration traits, from KERI's `TraitDex`: `EO` (establishment only), `DND` (do not delegate). */
  configTraits?: string[];
}

export interface InteractArgs {
  data?: Record<string, unknown>;
}

export interface RotateArgs {
  signingKeys: string[];
  signingThreshold?: Threshold;
  /** Digests of the next keys, not the keys themselves — see {@link nextKeyDigest}. */
  nextKeyDigests: string[];
  nextThreshold?: Threshold;
  data?: Record<string, unknown>;
  removeBackers?: string[];
  addBackers?: string[];
  backerThreshold?: number;
}

export interface DelegatedInceptArgs extends InceptArgs {
  delegator: string;
}

export type DelegatedRotateArgs = RotateArgs;

export type InceptEventBody = {
  v: string;
  t: "icp";
  d: string;
  i: string;
  s: string;
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  b: string[];
  c: string[];
  a: Record<string, unknown>[];
};

export type InteractEventBody = {
  v: string;
  t: "ixn";
  d: string;
  i: string;
  s: string;
  p: string;
  a: Record<string, unknown>[];
};

export type RotateEventBody = {
  v: string;
  t: "rot";
  d: string;
  i: string;
  s: string;
  p: string;
  kt: Threshold;
  k: string[];
  nt: Threshold;
  n: string[];
  bt: string;
  br: string[];
  ba: string[];
  a: Record<string, unknown>[];
};

export type DipEventBody = Omit<InceptEventBody, "t"> & { t: "dip"; di: string };

/** No `di`: v1 gives `drt` the same fields as `rot`. The delegator is established by the `dip`. */
export type DrtEventBody = Omit<RotateEventBody, "t"> & { t: "drt" };

export type KeyEventBody = {
  v: string;
  t: string;
  d: string;
  i: string;
  s: string;
  [key: string]: unknown;
};

/** KERI writes a threshold in hex: ten is `"a"`, sixteen is `"10"`. */
function toThreshold(count: number): string {
  return count.toString(16);
}

/**
 * Defaults to KERI's `ample`: the smallest threshold that still tolerates the
 * largest fault count the backer set admits. Not a plain majority — three
 * backers require all three.
 */
function backerThreshold(explicit: number | undefined, backers: string[]): string {
  if (explicit !== undefined) {
    return toThreshold(explicit);
  }

  const n = backers.length;
  if (n === 0) {
    return "0";
  }

  const least = Math.max(1, Math.floor((n - 1) / 3));
  const most = Math.max(1, Math.ceil((n - 1) / 3));
  return toThreshold(Math.min(n, Math.ceil((n + least + 1) / 2), Math.ceil((n + most + 1) / 2)));
}

/** A key event seal: what an anchoring event puts in its `a` to commit to `event`. */
export function keyEventSeal(event: Message<KeyEventBody>): { i: string; s: string; d: string } {
  return { i: event.body.i, s: event.body.s, d: event.body.d };
}

/**
 * Point `event` at the event that anchors it, as a `SealSourceCouple`.
 *
 * The couple names `anchoring` — the delegator's `ixn`, or the issuer's — not the event being
 * anchored, and renames its `s`/`d` to `snu`/`digest` on the way.
 */
export function attachSourceSeal(event: Message, anchoring: Message<KeyEventBody>): SealSourceCouple {
  const couple = { snu: anchoring.body.s, digest: anchoring.body.d };
  event.attachments.SealSourceCouples.push(couple);
  return couple;
}

/** The backer set a rotation establishes, which is the one that has to receipt it. */
export function applyBackerChanges(backers: string[], removed: string[], added: string[]): string[] {
  return backers.filter((backer) => !removed.includes(backer)).concat(added);
}

/**
 * The backer set that has to receipt `event`, and so the positions its witness signatures are
 * indexed by.
 *
 * A rotation is receipted by the set it establishes, not the one it replaces, so its own `br`/`ba`
 * decide. `state` is the key state the event applies to, and is only needed for a `dip`'s
 * successors — an inception carries its backers itself.
 */
export function backersFor(event: Message<KeyEventBody>, state: KeyState | null): string[] {
  const body = event.body;

  if (body.t === "icp" || body.t === "dip") {
    const { b } = body as InceptEventBody;
    return Array.isArray(b) ? b : [];
  }

  if (state === null) {
    throw new Error(`Backers of a ${body.t} come from the key state, which was not given`);
  }

  if (body.t === "rot" || body.t === "drt") {
    const rot = body as RotateEventBody | DrtEventBody;
    return applyBackerChanges(state.backers, rot.br, rot.ba);
  }

  return state.backers;
}

export function incept(args: InceptArgs): Message<InceptEventBody> {
  const keys = args.signingKeys;
  if (keys.length === 0) {
    throw new Error("No keys provided in inception event");
  }

  const backers = args.backers ?? [];
  const transferable = keys.length > 1 || isTransferable(keys[0]);
  const labels = transferable ? ["d", "i"] : ["d"];

  const body = encodeEvent<InceptEventBody>(
    {
      v: DUMMY_VERSION,
      t: "icp" as const,
      d: "",
      i: transferable ? "" : keys[0],
      s: "0",
      kt: args.signingThreshold ?? toThreshold(keys.length),
      k: keys,
      nt: args.nextThreshold ?? toThreshold(args.nextKeyDigests.length),
      n: args.nextKeyDigests,
      bt: backerThreshold(args.backerThreshold, backers),
      b: backers,
      c: args.configTraits ?? ([] as string[]),
      a: [] as Record<string, unknown>[],
    },
    { labels },
  );

  return new Message(body);
}

export function interact(state: KeyState, args: InteractArgs = {}): Message<InteractEventBody> {
  const body = encodeEvent<InteractEventBody>(
    {
      v: DUMMY_VERSION,
      t: "ixn" as const,
      d: "",
      i: state.identifier,
      s: (parseInt(state.lastEvent.s, 16) + 1).toString(16),
      p: state.lastEvent.d,
      a: args.data ? [args.data] : ([] as Record<string, unknown>[]),
    },
    { labels: ["d"] },
  );

  return new Message(body);
}

export function rotate(state: KeyState, args: RotateArgs): Message<RotateEventBody> {
  const keyDigest = state.nextKeyDigests[0];
  if (!keyDigest) {
    throw new Error(`State for id ${state.identifier} does not contain pre-committed next key digest`);
  }

  const body = encodeEvent<RotateEventBody>(
    {
      v: DUMMY_VERSION,
      t: "rot" as const,
      d: "",
      i: state.identifier,
      s: (parseInt(state.lastEvent.s, 16) + 1).toString(16),
      p: state.lastEvent.d,
      kt: args.signingThreshold ?? toThreshold(args.signingKeys.length),
      k: args.signingKeys,
      nt: args.nextThreshold ?? toThreshold(args.nextKeyDigests.length),
      n: args.nextKeyDigests,
      bt: backerThreshold(
        args.backerThreshold,
        applyBackerChanges(state.backers, args.removeBackers ?? [], args.addBackers ?? []),
      ),
      br: args.removeBackers ?? ([] as string[]),
      ba: args.addBackers ?? ([] as string[]),
      a: args.data ? [args.data] : ([] as Record<string, unknown>[]),
    },
    { labels: ["d"] },
  );

  return new Message(body);
}

export function delegatedIncept(args: DelegatedInceptArgs): Message<DipEventBody> {
  const keys = args.signingKeys;
  if (keys.length === 0) {
    throw new Error("No keys provided in inception event");
  }

  const backers = args.backers ?? [];

  const body = encodeEvent<DipEventBody>(
    {
      v: DUMMY_VERSION,
      t: "dip" as const,
      d: "",
      i: "",
      s: "0",
      kt: args.signingThreshold ?? toThreshold(keys.length),
      k: keys,
      nt: args.nextThreshold ?? toThreshold(args.nextKeyDigests.length),
      n: args.nextKeyDigests,
      bt: backerThreshold(args.backerThreshold, backers),
      b: backers,
      c: args.configTraits ?? ([] as string[]),
      a: [] as Record<string, unknown>[],
      di: args.delegator,
    },
    { labels: ["d", "i"] },
  );

  return new Message(body);
}

export function delegatedRotate(state: KeyState, args: DelegatedRotateArgs): Message<DrtEventBody> {
  if (state.delegator === undefined) {
    throw new Error(`State for id ${state.identifier} has no delegator; cannot delegated-rotate`);
  }

  const keyDigest = state.nextKeyDigests[0];
  if (!keyDigest) {
    throw new Error(`State for id ${state.identifier} does not contain pre-committed next key digest`);
  }

  const body = encodeEvent<DrtEventBody>(
    {
      v: DUMMY_VERSION,
      t: "drt" as const,
      d: "",
      i: state.identifier,
      s: (parseInt(state.lastEvent.s, 16) + 1).toString(16),
      p: state.lastEvent.d,
      kt: args.signingThreshold ?? toThreshold(args.signingKeys.length),
      k: args.signingKeys,
      nt: args.nextThreshold ?? toThreshold(args.nextKeyDigests.length),
      n: args.nextKeyDigests,
      bt: backerThreshold(
        args.backerThreshold,
        applyBackerChanges(state.backers, args.removeBackers ?? [], args.addBackers ?? []),
      ),
      br: args.removeBackers ?? ([] as string[]),
      ba: args.addBackers ?? ([] as string[]),
      a: args.data ? [args.data] : ([] as Record<string, unknown>[]),
    },
    { labels: ["d"] },
  );

  return new Message(body);
}

/** The `t` values that belong in a Key Event Log. `rct` is not one — a receipt is *about* an event. */
const KEL_EVENT_TYPES: ReadonlySet<string> = new Set(["icp", "ixn", "rot", "dip", "drt"]);

export function isKelEventType(t: unknown): boolean {
  return typeof t === "string" && KEL_EVENT_TYPES.has(t);
}

export function isKeyEvent(message: Message): message is Message<KeyEventBody> {
  return isKelEventType(message.body.t);
}

/**
 * Whether the event establishes keys — and so is signed by the keys it lists in
 * `k`, which for a rotation are the newly exposed ones. An `ixn` is signed by
 * the current state's keys instead.
 */
export function isEstablishment(t: unknown): boolean {
  return t === "icp" || t === "dip" || t === "rot" || t === "drt";
}
