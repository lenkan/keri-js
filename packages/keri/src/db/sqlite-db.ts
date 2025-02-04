import { DatabaseSync, type SupportedValueType } from "node:sqlite";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { KeyEvent } from "../events/main.ts";
import type { EventStore, KeyEventAttachment, KeyEventMessage, ListArgs } from "./event-store.ts";

function parseRow(row: unknown): KeyEventMessage {
  if (!row || typeof row !== "object") {
    throw new Error(`Row not found`);
  }

  const data = "event_data" in row && row["event_data"];

  if (!data || typeof data !== "string") {
    throw new Error(`Unexpected row format`);
  }

  if ("attachments" in row && typeof row["attachments"] !== "string") {
    throw new Error(`Unexpected row format`);
  }

  const attachments = JSON.parse(row["attachments"] || "[]");

  if (!Array.isArray(attachments)) {
    throw new Error(`Unexpected row format`);
  }

  return {
    event: JSON.parse(data),
    attachments: attachments.filter((att) => att.code && att.value),
  };
}

export interface SqliteEventStoreOptions {
  filename?: string;
}

function ensureDirSync(filename: string) {
  const dir = dirname(filename);
  if (!existsSync(dir)) {
    mkdirSync(dir);
  }
}

export class SqliteEventStore implements EventStore {
  #db: DatabaseSync;

  constructor(options: SqliteEventStoreOptions = {}) {
    if (options.filename) {
      ensureDirSync(options.filename);
    }

    this.#db = new DatabaseSync(options.filename ?? ":memory:");
  }

  init() {
    this.#db.exec(`
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            event_data JSON NOT NULL
        );
    `);

    this.#db.exec(`
        CREATE TABLE IF NOT EXISTS attachments (
            event_id TEXT NOT NULL,
            attachment_code TEXT NOT NULL,
            attachment_value TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES events(event_id)
            PRIMARY KEY(event_id, attachment_code, attachment_value)
        );
    `);
  }

  async saveEvent(event: KeyEvent) {
    const sql = `
      INSERT INTO events (event_id, event_data)
      VALUES ($id, $data) ON CONFLICT(event_id) DO NOTHING;
    `;

    this.#db.prepare(sql).run({
      id: event.d,
      data: JSON.stringify(event),
    });
  }

  async saveAttachment(id: string, attachment: KeyEventAttachment) {
    const sql = `
      INSERT INTO attachments (event_id, attachment_code, attachment_value)
      VALUES ($id, $group, $data)
      ON CONFLICT(event_id, attachment_code, attachment_value) DO NOTHING;
    `;

    this.#db.prepare(sql).run({
      id: id,
      group: attachment.code,
      data: attachment.value,
    });
  }

  async list(args: ListArgs = {}): Promise<KeyEventMessage[]> {
    const filter: string[] = [];
    const params: Record<string, SupportedValueType> = {};

    if (args.i) {
      filter.push("json_extract(event_data, '$.i') = $i");
      params["i"] = args.i;
    }

    if (args.d) {
      filter.push("json_extract(event_data, '$.d') = $d");
      params["d"] = args.d;
    }

    if (args.t) {
      filter.push("json_extract(event_data, '$.t') = $t");
      params["t"] = args.t;
    }

    if (args.r) {
      filter.push("json_extract(event_data, '$.r') = $r");
      params["r"] = args.r;
    }

    const sql = `
      SELECT
        event_data,
        json_group_array(json_object('code', attachment_code, 'value', attachment_value)) as attachments
      FROM
        events
        LEFT JOIN attachments ON events.event_id = attachments.event_id
      ${filter.length ? "WHERE " + filter.join(" AND ") : ""}
      GROUP BY events.event_id
      ORDER BY json_extract(event_data, '$.sn') DESC;
    `;

    const rows = this.#db.prepare(sql).all(params);
    return rows.map(parseRow);
  }
}
