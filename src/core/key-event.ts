import { Matter, Message } from "../cesr/__main__.ts";
import { DUMMY_VERSION, encodeEvent } from "./events.ts";
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
  nextKeys: string[];
  nextThreshold?: Threshold;
  wits?: string[];
  toad?: number;
}

export interface InteractArgs {
  data?: Record<string, unknown>;
}

export interface RotateArgs {
  signingKeys: string[];
  nextKeyDigests: string[];
  data?: Record<string, unknown>;
  br?: string[];
  ba?: string[];
  bt?: string;
}

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

export type KeyEvent<T extends KeyEventBody = KeyEventBody> = Message<T>;

export function incept(args: InceptArgs): KeyEvent<InceptEventBody> {
  const keys = args.signingKeys;
  if (keys.length === 0) {
    throw new Error("No keys provided in inception event");
  }

  const wits = args.wits ?? [];
  const transferable = keys.length > 1 || isTransferable(keys[0]);
  const labels = transferable ? ["d", "i"] : ["d"];

  let bt: string;
  if (args.toad !== undefined) {
    bt = args.toad.toString();
  } else if (wits.length === 0) {
    bt = "0";
  } else if (wits.length === 1) {
    bt = "1";
  } else {
    bt = (wits.length - 1).toString();
  }

  const body = encodeEvent<InceptEventBody>(
    {
      v: DUMMY_VERSION,
      t: "icp" as const,
      d: "",
      i: transferable ? "" : keys[0],
      s: "0",
      kt: keys.length.toString() as Threshold,
      k: keys,
      nt: args.nextKeys.length.toString() as Threshold,
      n: args.nextKeys,
      bt,
      b: wits,
      c: [] as string[],
      a: [] as Record<string, unknown>[],
    },
    { labels, legacy: true },
  );

  return new Message(body);
}

export function interact(state: KeyState, args: InteractArgs = {}): KeyEvent<InteractEventBody> {
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
    { labels: ["d"], legacy: true },
  );

  return new Message(body);
}

export function rotate(state: KeyState, args: RotateArgs): KeyEvent<RotateEventBody> {
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
      bt: args.bt ?? "0",
      br: args.br ?? ([] as string[]),
      ba: args.ba ?? ([] as string[]),
      c: [] as string[],
      a: args.data ? [args.data] : ([] as Record<string, unknown>[]),
    },
    { labels: ["d"], legacy: true },
  );

  return new Message(body);
}
