import type { Message } from "#keri/cesr";
import type { ReplyEventBody } from "./routed-event.ts";

export interface EndRoleRecord extends Record<string, unknown> {
  cid: string;
  role: string;
  eid: string;
}

export interface LocationRecord extends Record<string, unknown> {
  eid: string;
  scheme: string;
  url: string;
}

export interface Endpoint {
  aid: string;
  url: string;
  scheme: string;
  role: string;
}

export function resolveEndRole(
  replies: Iterable<Message<ReplyEventBody>>,
  cid: string,
  role: string,
): EndRoleRecord | null {
  // TODO: Needs verify against a Key Event Log
  // TODO: Needs to handle /end/role/cut
  let selected: EndRoleRecord | null = null;

  for (const message of replies) {
    if (message.body.t !== "rpy" || message.body.r !== "/end/role/add") {
      continue;
    }

    const record = message.body.a;

    if (
      typeof record !== "object" ||
      record === null ||
      !("eid" in record) ||
      typeof record.eid !== "string" ||
      !("cid" in record) ||
      typeof record.cid !== "string" ||
      !("role" in record) ||
      typeof record.role !== "string"
    ) {
      continue;
    }

    if (record.cid === cid && record.role === role) {
      selected = {
        cid: record.cid,
        role: record.role,
        eid: record.eid,
      };
    }
  }

  return selected;
}

export function resolveLocation(replies: Iterable<Message<ReplyEventBody>>, eid: string): LocationRecord | null {
  // TODO: Needs verify against a Key Event Log
  for (const message of replies) {
    if (message.body.t !== "rpy" || message.body.r !== "/loc/scheme") {
      continue;
    }

    const record = message.body.a;

    if (
      typeof record !== "object" ||
      record === null ||
      !("eid" in record) ||
      typeof record.eid !== "string" ||
      !("scheme" in record) ||
      typeof record.scheme !== "string" ||
      !("url" in record) ||
      typeof record.url !== "string"
    ) {
      continue;
    }

    if (!["http", "https"].includes(record.scheme)) {
      continue;
    }

    if (record.eid === eid) {
      return {
        eid: record.eid,
        scheme: record.scheme,
        url: record.url,
      };
    }
  }

  return null;
}
