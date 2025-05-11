import { DatabaseSync } from "node:sqlite";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { KeyValueStorage } from "../events/event-store.ts";

export interface SqliteStorageOptions {
  filename?: string;
}

function ensureDirSync(filename: string) {
  const dir = dirname(filename);
  if (!existsSync(dir)) {
    mkdirSync(dir);
  }
}

export class SqliteStorage implements KeyValueStorage {
  #db: DatabaseSync;

  constructor(options: SqliteStorageOptions = {}) {
    if (options.filename) {
      ensureDirSync(options.filename);
    }

    this.#db = new DatabaseSync(options.filename ?? ":memory:");
  }

  clear() {
    this.#db.exec("DELETE FROM events;");
  }

  init() {
    this.#db.exec(
      [
        "CREATE TABLE IF NOT EXISTS key_events (",
        "  event_id TEXT PRIMARY KEY,",
        "  event_data JSON NOT NULL",
        ");",
      ].join("\n"),
    );
  }

  async get(key: string): Promise<string | null> {
    const statement = ["SELECT event_data FROM key_events", "WHERE event_id = $event_id", "LIMIT 1;"].join("\n");

    const result = this.#db.prepare(statement).get({ event_id: key });
    if (!result || typeof result !== "object") {
      return null;
    }

    if (!("event_data" in result)) {
      throw new Error(`Row does not contain key: ${key}`);
    }

    const value = result["event_data"];

    if (typeof value !== "string") {
      throw new Error(`Row key "${key}" is not a string ${typeof value}`);
    }

    return value;
  }

  async set(key: string, value: string): Promise<void> {
    const statement = [
      "INSERT INTO key_events (event_id, event_data)",
      "VALUES ($event_id, $event_data)",
      "ON CONFLICT(event_id) DO UPDATE SET event_data = $event_data;",
    ].join("\n");

    this.#db.prepare(statement).run({ event_id: key, event_data: value ?? null });
  }
}
