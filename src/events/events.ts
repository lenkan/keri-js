import { blake3 } from "@noble/hashes/blake3";
import { cesr, MatterCode } from "cesr/__unstable__";

export type KeyEvent<T = Record<string, unknown>> = {
  v: string;
  t?: string;
  d: string;
  i?: string;
  s?: string;
} & T;

export type Threshold = string | string[];

export interface InceptEventInit {
  k: string[];
  kt?: Threshold;
  n?: string[];
  nt?: Threshold;
  b?: string[];
  bt?: string;
}

export type DelegatedInceptEvent = KeyEvent<InceptEvent & { t: "dip"; di: string }>;

export type InceptEvent = KeyEvent<{
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
}>;

export interface ExchangeEventInit {
  i: string;
  rp?: string;
  p?: string;
  dt?: string;
  r: string;
  q?: Record<string, unknown>;
  a?: Record<string, unknown>;
  e?: Record<string, unknown>;
}

export type ExchangeEvent = KeyEvent<{
  v: string;
  t: "exn";
  d: string;
  i: string;
  rp: string;
  p: string;
  r: string;
  q: Record<string, unknown>;
  a: Record<string, unknown>;
  e: Record<string, string | Record<string, unknown>>;
}>;

export interface InteractEventInit {
  i: string;
  s: string;
  p: string;
  a?: Record<string, unknown>[];
}

export type InteractEvent = KeyEvent<{
  v: string;
  t: "ixn";
  d: string;
  i: string;
  s: string;
  p: string;
  a: Record<string, unknown>[];
}>;

export interface QueryEventInit {
  dt?: Date;
  r?: string;
  rr?: string;
  q: Record<string, unknown>;
}

export type QueryEvent = KeyEvent<{
  v: string;
  t: "qry";
  d: string;
  dt: string;
  r: string;
  rr: string;
  q: Record<string, unknown>;
}>;

export interface ReceiptEventInit {
  d: string;
  i: string;
  s: string;
}

export type ReceiptEvent = KeyEvent<{
  v: string;
  t: "rct";
  d: string;
  i: string;
  s: string;
}>;

export interface ReplyEventInit {
  dt?: string;
  r: string;
  a: Record<string, unknown>;
}

export type ReplyEvent = KeyEvent<{
  v: string;
  t: "rpy";
  d: string;
  dt: string;
  r: string;
  a: Record<string, unknown>;
}>;

export interface RegistryInceptEventInit {
  ii: string;
  n?: string;
}

export type RegistryInceptEvent = KeyEvent<{
  t: "vcp";
  d: string;
  i: string;
  ii: string;
  s: string;
  c: string[];
  bt: string;
  b: string[];
  n: string;
}>;

export interface IssueEventInit {
  /**
   * Credential said
   */
  i: string;

  /**
   * Registry said
   */
  ri: string;
  dt?: string;
}

export type IssueEvent = KeyEvent<{
  t: "iss";
  d: string;

  /**
   * Credential said
   */
  i: string;
  s: string;

  /**
   * Registry said
   */
  ri: string;
  dt: string;
}>;

export interface CredentialInit {
  /**
   * Salty nonce
   */
  u?: string;
  i: string;
  ri: string;
  s: string;
  a: {
    i?: string;
    dt?: string;
    [key: string]: string | Record<string, unknown> | undefined;
  };
  r?: Record<string, unknown>;
  e?: Record<string, unknown>;
}

export interface CredentialSubject {
  /**
   * Subject SAID
   */
  d: string;

  /**
   * Issuee AID
   */
  i?: string;

  /**
   * Issuance timestamp
   */
  dt: string;

  [key: string]: string | undefined;
}

export interface CredentialRules {
  /**
   * Rules SAID
   */
  d: string;
  [key: string]: string | Record<string, unknown> | undefined;
}

export interface CredentialEdges {
  /**
   * Rules SAID
   */
  d: string;
  [key: string]: string | Record<string, unknown> | undefined;
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type CredentialEvent = {
  v: string;

  /**
   * Credential SAID
   */
  d: string;

  /**
   * Issuer AID
   */
  i: string;

  /**
   * Registry AID
   */
  ri: string;

  /**
   * Schema SAID
   */
  s: string;

  /**
   * Credential subject (claims)
   */
  a: CredentialSubject;

  /**
   * Credential rules
   */
  r: CredentialRules;

  /**
   * Credential edges
   */
  e?: CredentialEdges;
};

export function formatDate(date: Date) {
  return date.toISOString().replace("Z", "000+00:00");
}

export function randomNonce() {
  return cesr.encodeMatter({ code: MatterCode.Salt_128, raw: crypto.getRandomValues(new Uint8Array(16)) });
}

function calculateSaid(event: Record<string, unknown>): string {
  const encoder = new TextEncoder();

  const digest = cesr.encodeMatter({
    code: MatterCode.Blake3_256,
    raw: blake3
      .create({ dkLen: 32 })
      .update(encoder.encode(JSON.stringify(event)))
      .digest(),
  });

  return digest;
}

export function saidify<T extends Record<string, unknown>>(event: T, labels?: string[]): T {
  if (!labels?.length) {
    return event;
  }

  const digest = calculateSaid(event);

  for (const label of labels ?? []) {
    (event as Record<string, unknown>)[label] = digest;
  }

  return event;
}

function isTransferable(key: string) {
  const raw = cesr.decodeMatter(key);
  switch (raw.code) {
    case MatterCode.ECDSA_256k1N:
    case MatterCode.Ed25519N:
    case MatterCode.Ed448N:
      return false;
    default:
      return true;
  }
}

function resolveBackerThreshold(data: InceptEventInit) {
  if (data.bt) {
    return data.bt;
  }

  if (!data.b || data.b.length === 0) {
    return 0;
  }

  if (data.b.length === 1) {
    return 1;
  }

  return data.b.length - 1;
}

export interface KeriEventCreatorOptions {
  version: number;
}

export class KeriEventCreator {
  #version: number;

  constructor(options: KeriEventCreatorOptions) {
    this.#version = options.version;
  }

  #encode<T extends Record<string, unknown>>(data: T, labels: string[] = ["d"]): T & { v: "string" } {
    for (const label of labels) {
      if (!(label in data)) {
        throw new Error(`Input missing label '${label}'`);
      }

      (data as Record<string, unknown>)[label] = "#".repeat(44);
    }

    const event = JSON.parse(cesr.encodeMessage(data, { legacy: this.#version === 1 }));
    return saidify(event, labels);
  }

  registry(args: RegistryInceptEventInit): RegistryInceptEvent {
    return this.#encode(
      {
        t: "vcp",
        d: "",
        i: "",
        ii: args.ii,
        s: "0",
        c: ["NB"],
        bt: "0",
        b: [],
        n: args.n ?? randomNonce(),
      },
      ["d", "i"],
    );
  }

  issue(args: IssueEventInit): IssueEvent {
    return this.#encode({
      t: "iss",
      d: "",
      i: args.i,
      s: "0",
      ri: args.ri,
      dt: args.dt ?? formatDate(new Date()),
    });
  }

  incept(data: InceptEventInit): InceptEvent {
    if (data.k.length === 0) {
      throw new Error("No keys provided in inception event");
    }

    const transferable = data.k.length > 1 || isTransferable(data.k[0]);

    const labels = ["d"];
    if (transferable) {
      labels.push("i");
    }

    return this.#encode(
      {
        t: "icp" as const,
        d: "",
        i: transferable ? "" : data.k[0],
        s: "0",
        kt: data.kt ?? data.k.length.toString(),
        k: data.k,
        nt: data.nt ?? data.n?.length.toString() ?? "0",
        n: data.n ?? [],
        bt: resolveBackerThreshold(data).toString(),
        b: data.b ?? [],
        c: [] as string[],
        a: [],
      },
      labels,
    );
  }

  exchange(data: ExchangeEventInit): ExchangeEvent {
    return this.#encode({
      t: "exn",
      d: "",
      i: data.i,
      rp: data.rp || "",
      p: data.p || "",
      dt: data.dt || formatDate(new Date()),
      r: data.r,
      q: data.q || {},
      a: data.a || {},
      e: data.e ? saidify({ ...(data.e ?? {}), d: "" }, ["d"]) : {},
    });
  }

  interact(data: InteractEventInit): InteractEvent {
    return this.#encode({
      t: "ixn" as const,
      d: "",
      i: data.i,
      s: data.s,
      p: data.p,
      a: data.a ?? [],
    });
  }

  query(args: QueryEventInit): QueryEvent {
    return this.#encode({
      t: "qry" as const,
      d: "",
      dt: formatDate(args.dt ?? new Date()),
      r: args.r ?? "",
      rr: args.rr ?? "",
      q: args.q,
    });
  }

  receipt(data: ReceiptEventInit): ReceiptEvent {
    return this.#encode(
      {
        t: "rct" as const,
        d: data.d,
        i: data.i,
        s: data.s,
      },
      [],
    );
  }

  reply(data: ReplyEventInit): ReplyEvent {
    return this.#encode({
      t: "rpy" as const,
      d: "",
      dt: data.dt ?? formatDate(new Date()),
      r: data.r,
      a: data.a,
    });
  }

  credential(data: CredentialInit): CredentialEvent {
    const event = JSON.parse(
      cesr.encodeMessage(
        {
          d: "#".repeat(44),
          ...(data.u && { u: data.u }),
          i: data.i,
          ri: data.ri,
          s: data.s,
          a: saidify(
            {
              d: "#".repeat(44),
              ...data.a,
            },
            ["d"],
          ),
          ...(data.e && { e: saidify({ d: "#".repeat(44), ...data.e }, ["d"]) }),
          r: saidify({ d: "#".repeat(44), ...data.r }, ["d"]),
        },
        { legacy: this.#version === 1, protocol: "ACDC" },
      ),
    );

    return saidify(event, ["d"]);
  }
}

export const keri = new KeriEventCreator({ version: 1 });
