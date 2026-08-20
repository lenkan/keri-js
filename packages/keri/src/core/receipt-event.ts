import { Message } from "cesr";
import { DUMMY_VERSION, encodeEvent } from "./events.ts";
import type { KeyEventBody } from "./key-event.ts";

export type ReceiptEventBody = {
  v: string;
  t: "rct";
  d: string;
  i: string;
  s: string;
};

/**
 * Build the `rct` receipting `event`.
 *
 * Takes the event rather than its `d`/`i`/`s` because those three fields are
 * exactly what a receipt copies from it.
 *
 * Note `rct` is not itself a KEL event type — a receipt is *about* a key event.
 */
export function receipt(event: Message<KeyEventBody>): Message<ReceiptEventBody> {
  const body = encodeEvent<ReceiptEventBody>(
    {
      v: DUMMY_VERSION,
      t: "rct",
      d: event.body.d,
      i: event.body.i,
      s: event.body.s,
    },
    { labels: [] },
  );

  return new Message<ReceiptEventBody>(body);
}
