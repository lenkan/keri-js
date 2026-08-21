import type { Database } from "./sqlite-database.ts";

const migrations: string[][] = [
  // Migration 1: initial schema
  [
    [
      "CREATE TABLE IF NOT EXISTS event (",
      "  event_id    TEXT PRIMARY KEY,",
      "  protocol    TEXT NOT NULL,",
      "  type        TEXT NOT NULL,",
      "  sn          INTEGER,",
      "  event_json  JSON NOT NULL,",
      "  attachments TEXT",
      ")",
    ].join("\n"),
    [
      "CREATE TABLE IF NOT EXISTS key_info (",
      "  public_key            TEXT PRIMARY KEY,",
      "  public_key_digest     TEXT NOT NULL,",
      "  encrypted_private_key TEXT NOT NULL",
      ")",
    ].join("\n"),
  ],
  // Migration 2: mailbox cursor
  [
    [
      "CREATE TABLE IF NOT EXISTS mailbox_cursor (",
      "  prefix TEXT NOT NULL,",
      "  topic  TEXT NOT NULL,",
      "  offset INTEGER NOT NULL DEFAULT 0,",
      "  PRIMARY KEY (prefix, topic)",
      ")",
    ].join("\n"),
  ],
  // Migration 3: mailbox entry (server-side message store)
  [
    [
      "CREATE TABLE IF NOT EXISTS mailbox_entry (",
      "  id          INTEGER PRIMARY KEY AUTOINCREMENT,",
      "  pre         TEXT NOT NULL,",
      "  topic       TEXT NOT NULL,",
      "  event_json  JSON NOT NULL,",
      "  attachments TEXT",
      ")",
    ].join("\n"),
  ],
  // Migration 4: KERIpy-compatible mailbox ids — a dense per-(pre, topic)
  // ordinal starting at 0, replacing the global autoincrement. Destructive on
  // purpose: old rowid-based entries and cursors are meaningless against
  // ordinals, and every known database is in-memory or test-scoped.
  [
    "DROP TABLE IF EXISTS mailbox_entry",
    [
      "CREATE TABLE mailbox_entry (",
      "  pre         TEXT NOT NULL,",
      "  topic       TEXT NOT NULL,",
      "  ordinal     INTEGER NOT NULL,",
      "  event_json  JSON NOT NULL,",
      "  attachments TEXT,",
      "  PRIMARY KEY (pre, topic, ordinal)",
      ")",
    ].join("\n"),
    "DELETE FROM mailbox_cursor",
  ],
];

export function migrate(db: Database): void {
  db.execute(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`);
  db.execute(`INSERT INTO schema_version (version) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM schema_version)`);

  const row = Array.from(db.iterate("SELECT version FROM schema_version"))[0];
  let current = typeof row?.version === "number" ? row.version : 0;

  for (let i = current; i < migrations.length; i++) {
    db.transaction(() => {
      for (const statement of migrations[i]) {
        db.execute(statement);
      }
      db.execute(`UPDATE schema_version SET version = ${i + 1}`);
    });
    current = i + 1;
  }
}
