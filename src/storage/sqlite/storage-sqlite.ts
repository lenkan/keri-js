import type { DatabaseSync, SQLOutputValue, SQLInputValue } from "node:sqlite";
import { migrate } from "./schema.ts";
import {
  Message,
  Attachments,
  type KeyEvent,
  type RegistryInceptEvent,
  type IssueEvent,
  type RevokeEvent,
  type ReplyEvent,
  type KeyEventBody,
  type CredentialBody,
} from "#keri/core";
import type { MessageBody } from "cesr";
import type { ControllerStorage } from "../../controller/controller.ts";

function parseRow<T extends MessageBody>(result: Record<string, SQLOutputValue>): Message<T> {
  if (!("event_json" in result) || typeof result.event_json !== "string") {
    throw new Error("Row does not contain event_json");
  }

  if (!("attachments" in result) || typeof result.attachments !== "string") {
    throw new Error("Row does not contain attachments");
  }

  const body = JSON.parse(result.event_json);
  const atc = Attachments.parse(new TextEncoder().encode(result.attachments)) ?? new Attachments();

  return new Message(body, atc);
}

// eslint-disable-next-line @typescript-eslint/consistent-type-definitions
type RowInput = {
  event_id: string | null;
  protocol: string | null;
  type: string | null;
  sn: number | null;
  event_json: string;
  attachments: string;
};

function prepareRow<T extends MessageBody>(message: Message<T>): RowInput {
  if (message.version.protocol === "ACDC") {
    const body = message.body as unknown as CredentialBody;
    return {
      event_id: body.d,
      protocol: message.version.protocol,
      type: "credential",
      sn: null,
      event_json: JSON.stringify(body),
      attachments: message.attachments.text(),
    };
  }

  switch (message.body.t) {
    case "icp":
    case "rot":
    case "ixn": {
      const body = message.body as unknown as KeyEventBody;
      return {
        event_id: body.d,
        protocol: message.version.protocol,
        type: body.t,
        sn: parseInt(body.s, 16),
        event_json: JSON.stringify(body),
        attachments: message.attachments.text(),
      };
    }
    case "vcp": {
      const body = message.body as unknown as RegistryInceptEvent;
      return {
        event_id: body.d,
        protocol: message.version.protocol,
        type: body.t,
        sn: null,
        event_json: JSON.stringify(body),
        attachments: message.attachments.text(),
      };
    }
    case "iss":
    case "rev": {
      const body = message.body as unknown as IssueEvent | RevokeEvent;
      return {
        event_id: body.d,
        protocol: message.version.protocol,
        type: body.t,
        sn: null,
        event_json: JSON.stringify(body),
        attachments: message.attachments.text(),
      };
    }
    default: {
      const body = message.body as unknown as MessageBody;
      return {
        event_id: typeof body.d === "string" ? body.d : null,
        protocol: message.version.protocol,
        type: typeof body.t === "string" ? body.t : null,
        sn: null,
        event_json: JSON.stringify(body),
        attachments: message.attachments.text(),
      };
    }
  }
}

export class SqliteControllerStorage implements ControllerStorage {
  #db: DatabaseSync;

  constructor(db: DatabaseSync) {
    migrate(db);
    this.#db = db;
  }

  saveKey(publicKey: string, digest: string, encryptedPrivKey: string): void {
    const statement = [
      "INSERT INTO key_info(public_key, public_key_digest, encrypted_private_key)",
      "VALUES ($public_key, $digest, $encrypted_private_key)",
      "ON CONFLICT (public_key) DO NOTHING;",
    ].join("\n");

    this.#db.prepare(statement).run({
      public_key: publicKey,
      digest,
      encrypted_private_key: encryptedPrivKey,
    });
  }

  getKey(publicKey: string): string {
    const statement = ["SELECT encrypted_private_key FROM key_info", "WHERE public_key = $public_key", "LIMIT 1;"].join(
      "\n",
    );

    const result = this.#db.prepare(statement).get({ public_key: publicKey });
    if (
      !result ||
      typeof result !== "object" ||
      !("encrypted_private_key" in result) ||
      typeof result.encrypted_private_key !== "string"
    ) {
      throw new Error(`Key not found for public key: ${publicKey}`);
    }

    return result.encrypted_private_key;
  }

  getPublicKeyByDigest(digest: string): string {
    const statement = ["SELECT public_key FROM key_info", "WHERE public_key_digest = $digest", "LIMIT 1;"].join("\n");

    const result = this.#db.prepare(statement).get({ digest });
    if (!result || typeof result !== "object" || !("public_key" in result) || typeof result.public_key !== "string") {
      throw new Error(`Key not found for digest: ${digest}`);
    }

    return result.public_key;
  }

  saveMessage(message: Message): void {
    const statement = [
      "INSERT INTO event(event_id, protocol, type, sn, event_json, attachments)",
      "VALUES ($event_id, $protocol, $type, $sn, $event_json, $attachments)",
      "ON CONFLICT(event_id) DO NOTHING;",
    ].join("\n");

    this.#db.prepare(statement).run(prepareRow(message));
  }

  *getReplies(filter: { route?: string; eid?: string; cid?: string } = {}): Generator<Message<ReplyEvent>> {
    const conditions: string[] = ["type = 'rpy'"];
    const params: Record<string, SQLInputValue> = {};

    if (filter.eid !== undefined) {
      conditions.push("json_extract(event_json, '$.a.eid') = $eid");
      params.eid = filter.eid;
    }

    if (filter.route !== undefined) {
      conditions.push("json_extract(event_json, '$.r') = $route");
      params.route = filter.route;
    }

    if (filter.cid !== undefined) {
      conditions.push("json_extract(event_json, '$.a.cid') = $cid");
      params.cid = filter.cid;
    }

    const statement = [
      "SELECT event_json, attachments FROM event",
      "WHERE " + conditions.join(" AND "),
      "ORDER BY sn ASC",
    ].join("\n");

    for (const result of this.#db.prepare(statement).iterate(params)) {
      yield parseRow(result);
    }
  }

  *getKeyEvents(prefix: string): Generator<KeyEvent> {
    const statement = [
      "SELECT event_json, attachments",
      "FROM event",
      "WHERE json_extract(event_json, '$.i') = $prefix",
      "AND type in ('icp', 'rot', 'ixn')",
      "ORDER BY sn ASC",
    ].join("\n");

    for (const result of this.#db.prepare(statement).iterate({ prefix })) {
      yield parseRow(result);
    }
  }

  *getCredentialEvents(id: string): Generator<Message<IssueEvent | RevokeEvent>> {
    const statement = [
      "SELECT event_json, attachments",
      "FROM event",
      "WHERE type IN ('iss', 'rev') AND json_extract(event_json, '$.i') = $id",
      "ORDER BY rowid ASC",
    ].join("\n");

    for (const row of this.#db.prepare(statement).iterate({ id })) {
      yield parseRow<IssueEvent | RevokeEvent>(row);
    }
  }

  getRegistry(id: string): Message<RegistryInceptEvent> | null {
    const statement = [
      "SELECT event_json, attachments",
      "FROM event",
      "WHERE type = 'vcp' AND json_extract(event_json, '$.i') = $id",
      "LIMIT 1",
    ].join("\n");

    const result = this.#db.prepare(statement).get({ id });
    return result ? parseRow(result) : null;
  }

  *getRegistriesByOwner(owner: string): Generator<Message<RegistryInceptEvent>> {
    const statement = [
      "SELECT event_json, attachments",
      "FROM event",
      "WHERE type = 'vcp' AND json_extract(event_json, '$.ii') = $owner",
      "ORDER BY rowid ASC",
    ].join("\n");

    for (const row of this.#db.prepare(statement).iterate({ owner })) {
      yield parseRow<RegistryInceptEvent>(row);
    }
  }

  getCredential(id: string): CredentialBody | null {
    const statement = ["SELECT event_json, attachments", "FROM event", "WHERE event_id = $id", "LIMIT 1"].join("\n");

    const result = this.#db.prepare(statement).get({ id });
    return result ? (parseRow(result).body as CredentialBody) : null;
  }

  getCredentialsByRegistry(registryId: string): CredentialBody[] {
    const statement = [
      "SELECT event_json, attachments",
      "FROM event",
      "WHERE json_extract(event_json, '$.ri') = $registry_id",
    ].join("\n");

    return this.#db
      .prepare(statement)
      .all({ registry_id: registryId })
      .map((row) => parseRow(row).body as CredentialBody);
  }

  getMailboxOffset(prefix: string, topic: string): number {
    const result = this.#db
      .prepare("SELECT offset FROM mailbox_cursor WHERE prefix = $prefix AND topic = $topic LIMIT 1")
      .get({ prefix, topic });
    return result && typeof result === "object" && "offset" in result && typeof result.offset === "number"
      ? result.offset
      : 0;
  }

  saveMailboxOffset(prefix: string, topic: string, offset: number): void {
    this.#db
      .prepare(
        "INSERT INTO mailbox_cursor(prefix, topic, offset) VALUES ($prefix, $topic, $offset) " +
          "ON CONFLICT(prefix, topic) DO UPDATE SET offset = $offset",
      )
      .run({ prefix, topic, offset });
  }
}
