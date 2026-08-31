import { Message } from "../cesr/main.ts";
import { DUMMY_VERSION, encodeEvent, formatDate } from "../events/main.ts";

export interface IssueEventArgs {
  /**
   * Credential SAID
   */
  i: string;

  /**
   * Registry SAID
   */
  ri: string;
  dt?: Date;
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
  dt?: Date;
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
      dt: formatDate(args.dt ?? new Date()),
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
      dt: formatDate(args.dt ?? new Date()),
    },
    { labels: ["d"] },
  );

  return new Message(body);
}
