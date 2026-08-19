import { Matter, Message } from "cesr";
import { DUMMY_VERSION, encodeEvent, type ProtocolVersion } from "./events.ts";
import type { Threshold } from "./threshold.ts";

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
  version?: ProtocolVersion;
}

export interface InteractArgs {
  data?: Record<string, unknown>;
  version?: ProtocolVersion;
}

export interface RotateArgs {
  signingKeys: string[];
  /** Digests of the next keys, not the keys themselves — see {@link nextKeyDigest}. */
  nextKeyDigests: string[];
  data?: Record<string, unknown>;
  removeBackers?: string[];
  addBackers?: string[];
  backerThreshold?: number;
  version?: ProtocolVersion;
}

export interface DelegatedInceptArgs extends InceptArgs {
  delegator: string;
}

export type DelegatedRotateArgs = RotateArgs;

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
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
  c: string[];
  a: Record<string, unknown>[];
};

export type DipEventBody = Omit<InceptEventBody, "t"> & { t: "dip"; di: string };

export type DrtEventBody = Omit<RotateEventBody, "t"> & { t: "drt"; di: string };

function isTransferable(key: string) {
  const raw = Matter.parse(key);
  switch (raw.code) {
    case Matter.Code.ECDSA_256k1N:
    case Matter.Code.Ed25519N:
    case Matter.Code.Ed448N:
      return false;
    default:
      return true;
  }
}

export type KeyEventBody = {
  v: string;
  t: string;
  d: string;
  i: string;
  s: string;
  [key: string]: unknown;
};

/** Default backer threshold: all but one, so a single backer is still required. */
function defaultBackerThreshold(backers: string[]): string {
  if (backers.length === 0) {
    return "0";
  }

  return backers.length === 1 ? "1" : (backers.length - 1).toString();
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
      kt: keys.length.toString() as Threshold,
      k: keys,
      nt: args.nextKeyDigests.length.toString() as Threshold,
      n: args.nextKeyDigests,
      bt: args.backerThreshold?.toString() ?? defaultBackerThreshold(backers),
      b: backers,
      c: [] as string[],
      a: [] as Record<string, unknown>[],
    },
    { labels, version: args.version },
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
    { labels: ["d"], version: args.version },
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
      kt: "1",
      k: args.signingKeys,
      nt: "1",
      n: args.nextKeyDigests,
      bt: args.backerThreshold?.toString() ?? "0",
      br: args.removeBackers ?? ([] as string[]),
      ba: args.addBackers ?? ([] as string[]),
      c: [] as string[],
      a: args.data ? [args.data] : ([] as Record<string, unknown>[]),
    },
    { labels: ["d"], version: args.version },
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
      kt: keys.length.toString() as Threshold,
      k: keys,
      nt: args.nextKeyDigests.length.toString() as Threshold,
      n: args.nextKeyDigests,
      bt: args.backerThreshold?.toString() ?? defaultBackerThreshold(backers),
      b: backers,
      c: [] as string[],
      a: [] as Record<string, unknown>[],
      di: args.delegator,
    },
    { labels: ["d", "i"], version: args.version },
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
      kt: "1",
      k: args.signingKeys,
      nt: "1",
      n: args.nextKeyDigests,
      bt: args.backerThreshold?.toString() ?? "0",
      br: args.removeBackers ?? ([] as string[]),
      ba: args.addBackers ?? ([] as string[]),
      c: [] as string[],
      a: args.data ? [args.data] : ([] as Record<string, unknown>[]),
      di: state.delegator,
    },
    { labels: ["d"], version: args.version },
  );

  return new Message(body);
}

const KEL_EVENT_TYPES = new Set(["icp", "ixn", "rot", "dip", "drt"]);

export function isKeyEvent(message: Message): message is Message<KeyEventBody> {
  return KEL_EVENT_TYPES.has(message.body.t as string);
}
