import { Message } from "../cesr/__main__.ts";
import { DUMMY_VERSION, encodeEvent } from "./events.ts";

export interface ReceiptEventInit {
  d: string;
  i: string;
  s: string;
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type ReceiptEventBody = {
  v: string;
  t: "rct";
  d: string;
  i: string;
  s: string;
};

export type ReceiptEvent = Message<ReceiptEventBody>;

export function receipt(args: ReceiptEventInit): ReceiptEvent {
  const body = encodeEvent<ReceiptEventBody>(
    {
      v: DUMMY_VERSION,
      t: "rct",
      d: args.d,
      i: args.i,
      s: args.s,
    },
    { labels: [] },
  );

  return new Message<ReceiptEventBody>(body);
}
