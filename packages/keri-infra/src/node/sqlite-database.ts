export type SQLValue = string | number | null | Uint8Array;
export type Params = Record<string, SQLValue>;
export type Row = Record<string, SQLValue>;

export interface Database {
  /**
   * Execute a statement that produces no rows (DDL, DML, transaction control).
   */
  execute(sql: string, params?: Params): void;

  /**
   * Iterate over matching rows one at a time without loading all into memory.
   */
  iterate(sql: string, params?: Params): Iterable<Row>;
}
