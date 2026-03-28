import { Message } from "cesr";
import { DUMMY_VERSION, encodeEvent, formatDate } from "./events.ts";

export interface IssueEventInit {
  /**
   * Credential SAID
   */
  i: string;

  /**
   * Registry SAID
   */
  ri: string;
  dt?: string;
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type IssueEvent = {
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

export interface RevokeEventInit {
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
  dt?: string;
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
export type RevokeEvent = {
  v: string;
  t: "rev";
  d: string;
  i: string;
  s: string;
  ri: string;
  p: string;
  dt: string;
};

export function issue(args: IssueEventInit) {
  const body = encodeEvent<IssueEvent>(
    {
      v: DUMMY_VERSION,
      t: "iss",
      d: "",
      i: args.i,
      s: "0",
      ri: args.ri,
      dt: args.dt ?? formatDate(new Date()),
    },
    { labels: ["d"] },
  );

  return new Message(body);
}

export function revoke(args: RevokeEventInit) {
  const body = encodeEvent<RevokeEvent>(
    {
      v: DUMMY_VERSION,
      t: "rev",
      d: "",
      i: args.i,
      s: "1",
      ri: args.ri,
      p: args.p,
      dt: args.dt ?? formatDate(new Date()),
    },
    { labels: ["d"] },
  );

  return new Message(body);
}
