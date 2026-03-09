import type { DatabaseSync } from "node:sqlite";

const migrations: string[] = [
  // Migration 1: initial schema
  `
  CREATE TABLE IF NOT EXISTS event (
    event_id    TEXT PRIMARY KEY,
    protocol    TEXT NOT NULL,
    type        TEXT NOT NULL,
    sn          INTEGER,
    event_json  JSON NOT NULL,
    attachments TEXT
  );
  CREATE TABLE IF NOT EXISTS key_info (
    public_key            TEXT PRIMARY KEY,
    public_key_digest     TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL
  );
  `,
  // Migration 2: mailbox cursor
  `
  CREATE TABLE IF NOT EXISTS mailbox_cursor (
    prefix TEXT NOT NULL,
    topic  TEXT NOT NULL,
    offset INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (prefix, topic)
  );
  `,
];

export function migrate(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_version (
      version INTEGER NOT NULL
    );
    INSERT INTO schema_version (version)
      SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
  `);

  const row = db.prepare("SELECT version FROM schema_version").get() as { version: number };
  let current = row.version;

  for (let i = current; i < migrations.length; i++) {
    db.exec("BEGIN");
    try {
      db.exec(migrations[i]);
      db.exec(`UPDATE schema_version SET version = ${i + 1}`);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    current = i + 1;
  }
}
