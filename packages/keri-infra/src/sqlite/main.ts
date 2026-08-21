/**
 * SQLite-backed storage, pure over the {@link Database} interface — no
 * platform bindings. Pair it with a driver: `NodeSqliteDatabase` from the
 * `node` submodule, or a Durable Object adapter in a worker.
 */
export { migrate } from "./schema.ts";
export type { Database, Params, Row, SQLValue } from "./sqlite-database.ts";
export { SqliteControllerStorage } from "./sqlite-storage.ts";
