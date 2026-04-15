import { migrate } from "./schema.ts";
import type { Database, Params, Row } from "./sqlite-database.ts";

export { NodeSqliteDatabase } from "./node-sqlite.ts";
export type { Database, Params, Row, SQLValue } from "./sqlite-database.ts";

import type { MessageBody } from "../../cesr/__main__.ts";
import {
  Attachments,
  type CredentialBody,
  type IssueEvent,
  type KeyEvent,
  type KeyEventBody,
  Message,
  type RegistryInceptEventBody,
  type ReplyEventBody,
  type RevokeEvent,
} from "../../core/main.ts";
import type { CredentialStorage } from "../credential-storage.ts";
import type { KeyEventStorage } from "../key-event-storage.ts";
import type { MailboxStorage } from "../mailbox-storage.ts";
import type { PrivateKeyStorage } from "../private-key-storage.ts";

function parseRow<T extends MessageBody>(result: Row): Message<T> {
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
      const body = message.body as unknown as RegistryInceptEventBody;
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

export class SqliteControllerStorage implements KeyEventStorage, PrivateKeyStorage, CredentialStorage, MailboxStorage {
  #db: Database;

  constructor(db: Database) {
    migrate(db);
    this.#db = db;
  }

  #queryOne(sql: string, params?: Params): Row | undefined {
    const result = Array.from(this.#db.iterate(sql, params))[0];
    return result ? (result as Row) : undefined;
  }

  saveKey(publicKey: string, digest: string, encryptedPrivKey: string): void {
    const statement = [
      "INSERT INTO key_info(public_key, public_key_digest, encrypted_private_key)",
      "VALUES ($public_key, $digest, $encrypted_private_key)",
      "ON CONFLICT (public_key) DO NOTHING",
    ].join("\n");

    this.#db.execute(statement, {
      public_key: publicKey,
      digest,
      encrypted_private_key: encryptedPrivKey,
    });
  }

  getEncryptedPrivateKey(publicKey: string): string {
    const statement = ["SELECT encrypted_private_key FROM key_info", "WHERE public_key = $public_key", "LIMIT 1"].join(
      "\n",
    );

    const result = this.#queryOne(statement, { public_key: publicKey });
    if (!result || typeof result.encrypted_private_key !== "string") {
      throw new Error(`Key not found for public key: ${publicKey}`);
    }

    return result.encrypted_private_key;
  }

  getPublicKeyByDigest(digest: string): string {
    const statement = ["SELECT public_key FROM key_info", "WHERE public_key_digest = $digest", "LIMIT 1"].join("\n");

    const result = this.#queryOne(statement, { digest });
    if (!result || typeof result.public_key !== "string") {
      throw new Error(`Key not found for digest: ${digest}`);
    }

    return result.public_key;
  }

  saveMessage(message: Message): void {
    const statement = [
      "INSERT INTO event(event_id, protocol, type, sn, event_json, attachments)",
      "VALUES ($event_id, $protocol, $type, $sn, $event_json, $attachments)",
      "ON CONFLICT(event_id) DO NOTHING",
    ].join("\n");

    this.#db.execute(statement, prepareRow(message));
  }

  *getReplies(filter: { route?: string; eid?: string; cid?: string } = {}): Generator<Message<ReplyEventBody>> {
    const conditions: string[] = ["type = 'rpy'"];
    const params: Record<string, string> = {};

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
      `WHERE ${conditions.join(" AND ")}`,
      "ORDER BY sn ASC",
    ].join("\n");

    for (const result of this.#db.iterate(statement, params)) {
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

    for (const result of this.#db.iterate(statement, { prefix })) {
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

    for (const row of this.#db.iterate(statement, { id })) {
      yield parseRow<IssueEvent | RevokeEvent>(row);
    }
  }

  getRegistry(id: string): Message<RegistryInceptEventBody> | null {
    const statement = [
      "SELECT event_json, attachments",
      "FROM event",
      "WHERE type = 'vcp' AND json_extract(event_json, '$.i') = $id",
      "LIMIT 1",
    ].join("\n");

    const result = this.#queryOne(statement, { id });
    return result ? parseRow(result) : null;
  }

  *getRegistriesByOwner(owner: string): Generator<Message<RegistryInceptEventBody>> {
    const statement = [
      "SELECT event_json, attachments",
      "FROM event",
      "WHERE type = 'vcp' AND json_extract(event_json, '$.ii') = $owner",
      "ORDER BY rowid ASC",
    ].join("\n");

    for (const row of this.#db.iterate(statement, { owner })) {
      yield parseRow<RegistryInceptEventBody>(row);
    }
  }

  getCredential(id: string): CredentialBody | null {
    const statement = ["SELECT event_json, attachments", "FROM event", "WHERE event_id = $id", "LIMIT 1"].join("\n");

    const result = this.#queryOne(statement, { id });
    return result ? (parseRow(result).body as CredentialBody) : null;
  }

  getCredentialsByRegistry(registryId: string): CredentialBody[] {
    const statement = [
      "SELECT event_json, attachments",
      "FROM event",
      "WHERE json_extract(event_json, '$.ri') = $registry_id",
    ].join("\n");

    return Array.from(this.#db.iterate(statement, { registry_id: registryId })).map(
      (row) => parseRow(row).body as CredentialBody,
    );
  }

  getMailboxOffset(prefix: string, topic: string): number {
    const result = this.#queryOne(
      "SELECT offset FROM mailbox_cursor WHERE prefix = $prefix AND topic = $topic LIMIT 1",
      { prefix, topic },
    );
    return typeof result?.offset === "number" ? result.offset : 0;
  }

  saveMailboxOffset(prefix: string, topic: string, offset: number): void {
    this.#db.execute(
      "INSERT INTO mailbox_cursor(prefix, topic, offset) VALUES ($prefix, $topic, $offset) " +
        "ON CONFLICT(prefix, topic) DO UPDATE SET offset = $offset",
      { prefix, topic, offset },
    );
  }
}
