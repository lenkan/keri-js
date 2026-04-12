import { Message } from "../cesr/__main__.ts";
import { DUMMY_VERSION, encodeEvent, randomNonce } from "./events.ts";

export interface RegistryInceptEventInit {
  ii: string;
  n?: string;
}

export type RegistryInceptEventBody = {
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

export type RegistryEventBody = {
  v: string;
  t: string;
  d: string;
  i: string;
  [key: string]: unknown;
};

export type RegistryEvent = Message<RegistryEventBody>;

export function incept(args: RegistryInceptEventInit): Message<RegistryInceptEventBody> {
  const body = encodeEvent<RegistryInceptEventBody>(
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
