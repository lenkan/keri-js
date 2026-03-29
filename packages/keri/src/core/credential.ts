import { Message, VersionString } from "cesr";
import { encodeEvent } from "./events.ts";
import { saidify } from "./said.ts";

export interface CredentialBodyInit {
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
  dt?: string;

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
export type CredentialBody = {
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

export type Credential = Message<CredentialBody>;

export function createCredential(data: CredentialBodyInit): Credential {
  const body = encodeEvent<CredentialBody>({
    v: VersionString.encode({
      protocol: "ACDC",
      kind: "JSON",
      legacy: true,
    }),
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
  });

  return new Message<CredentialBody>(body);
}
