import { Message } from "cesr";
import { DUMMY_VERSION, encodeEvent, type ProtocolVersion } from "./events.ts";

export interface ReceiptEventArgs {
  d: string;
  i: string;
  s: string;
  version?: ProtocolVersion;
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type ReceiptEventBody = {
  v: string;
  t: "rct";
  d: string;
  i: string;
  s: string;
};

export function receipt(args: ReceiptEventArgs): Message<ReceiptEventBody> {
  const body = encodeEvent<ReceiptEventBody>(
    {
      v: DUMMY_VERSION,
      t: "rct",
      d: args.d,
      i: args.i,
      s: args.s,
    },
    { labels: [], version: args.version },
  );

  return new Message<ReceiptEventBody>(body);
}
