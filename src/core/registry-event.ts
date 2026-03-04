import { Message } from "cesr";
import { DUMMY_VERSION, encodeEvent, randomNonce } from "./events.ts";

export interface RegistryInceptEventInit {
  ii: string;
  n?: string;
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type RegistryInceptEvent = {
  v: string;
  t: "vcp";
  d: string;
  i: string;
  ii: string;
  s: string;
  c: string[];
  bt: string;
  b: string[];
  n: string;
};

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type RegistryEventBody = {
  v: string;
  t: string;
  d: string;
  i: string;
  [key: string]: unknown;
};

export type RegistryEvent = Message<RegistryEventBody>;

export function incept(args: RegistryInceptEventInit) {
  const body = encodeEvent<RegistryInceptEvent>(
    {
      v: DUMMY_VERSION,
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
    { labels: ["d", "i"], legacy: true },
  );

  return new Message(body);
}
