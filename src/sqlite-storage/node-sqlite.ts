import type { DatabaseSync } from "node:sqlite";
import type { Database, Params, Row } from "./sqlite-database.ts";

/**
 * Adapter that wraps the built-in `node:sqlite` `DatabaseSync` class so it satisfies the `Database` interface.
 */
export class NodeSqliteDatabase implements Database {
  #db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.#db = db;
  }

  execute(sql: string, params?: Params): void {
    if (params !== undefined) {
      this.#db.prepare(sql).run(params);
    } else {
      this.#db.exec(sql);
    }
  }

  queryOne(sql: string, params?: Params): Row | undefined {
    const result = this.#db.prepare(sql).get(params ?? {});
    return result as Row | undefined;
  }

  iterate(sql: string, params?: Params): Iterable<Row> {
    return this.#db.prepare(sql).iterate(params ?? {}) as Iterable<Row>;
  }
}
