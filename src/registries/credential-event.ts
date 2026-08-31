import { Message } from "../cesr/main.ts";
import { DUMMY_VERSION, encodeEvent, formatDate } from "../events/main.ts";

/**
 * A `Date` holds milliseconds, KERI writes microseconds, and the SAID is computed over the text.
 * So a timestamp that came off the wire is passed through rather than round-tripped through
 * `Date`, which would round `…019676` to `…019000` and change the event's digest.
 */
function timestamp(dt: Date | string | undefined): string {
  return typeof dt === "string" ? dt : formatDate(dt ?? new Date());
}

export interface IssueEventArgs {
  /**
   * Credential SAID
   */
  i: string;

  /**
   * Registry SAID
   */
  ri: string;
  dt?: Date | string;
}

export type IssueEventBody = {
  v: string;
  t: "iss";
  d: string;

  /**
   * Credential SAID
   */
  i: string;
  s: string;

  /**
   * Registry SAID
   */
  ri: string;
  dt: string;
};

export interface RevokeEventArgs {
  /**
   * Credential SAID
   */
  i: string;

  /**
   * Registry SAID
   */
  ri: string;

  /**
   * Issuance event SAID
   */
  p: string;
  dt?: Date | string;
}

export type RevokeEventBody = {
  v: string;
  t: "rev";
  d: string;
  i: string;
  s: string;
  ri: string;
  p: string;
  dt: string;
};

export function issue(args: IssueEventArgs): Message<IssueEventBody> {
  const body = encodeEvent<IssueEventBody>(
    {
      v: DUMMY_VERSION,
      t: "iss",
      d: "",
      i: args.i,
      s: "0",
      ri: args.ri,
      dt: timestamp(args.dt),
    },
    { labels: ["d"] },
  );

  return new Message(body);
}

export function revoke(args: RevokeEventArgs): Message<RevokeEventBody> {
  const body = encodeEvent<RevokeEventBody>(
    {
      v: DUMMY_VERSION,
      t: "rev",
      d: "",
      i: args.i,
      s: "1",
      ri: args.ri,
      p: args.p,
      dt: timestamp(args.dt),
    },
    { labels: ["d"] },
  );

  return new Message(body);
}
