import type { Database } from "./sqlite-database.ts";

const migrations: string[][] = [
  // Migration 1: initial schema
  [
    `CREATE TABLE IF NOT EXISTS event (
      event_id    TEXT PRIMARY KEY,
      protocol    TEXT NOT NULL,
      type        TEXT NOT NULL,
      sn          INTEGER,
      event_json  JSON NOT NULL,
      attachments TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS key_info (
      public_key            TEXT PRIMARY KEY,
      public_key_digest     TEXT NOT NULL,
      encrypted_private_key TEXT NOT NULL
    )`,
  ],
  // Migration 2: mailbox cursor
  [
    `CREATE TABLE IF NOT EXISTS mailbox_cursor (
      prefix TEXT NOT NULL,
      topic  TEXT NOT NULL,
      offset INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (prefix, topic)
    )`,
  ],
];

export function migrate(db: Database): void {
  db.execute(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`);
  db.execute(`INSERT INTO schema_version (version) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM schema_version)`);

  const row = Array.from(db.iterate("SELECT version FROM schema_version"))[0];
  let current = typeof row?.version === "number" ? row.version : 0;

  for (let i = current; i < migrations.length; i++) {
    db.execute("BEGIN");
    try {
      for (const statement of migrations[i]) {
        db.execute(statement);
      }
      db.execute(`UPDATE schema_version SET version = ${i + 1}`);
      db.execute("COMMIT");
    } catch (err) {
      db.execute("ROLLBACK");
      throw err;
    }
    current = i + 1;
  }
}
