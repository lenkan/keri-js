export interface Entry {
  key: string;
  value: string;
}

export interface ScanOptions {
  /** Inclusive lower bound. Must sort at or after `prefix`. */
  start?: string;
  limit?: number;
}

/**
 * The whole storage surface a witness needs. Values are opaque: only the
 * witness knows what is inside them.
 *
 * Async because the backends are: Deno KV and DynamoDB have no synchronous API
 * at all. Durable Object SQLite and `node:sqlite` are synchronous underneath and
 * lose nothing by returning already-resolved promises.
 *
 * Key events are written without a conditional check, so two writers racing on
 * the same AID can each miss the other's duplicity check. Serialize writes per
 * AID — a Durable Object per witness, or a single process — or accept that a
 * duplicitous pair submitted simultaneously may both be stored.
 */
export interface Store {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;

  /** Ascending by key. Callers must not write to `prefix` while reading, so an adapter may stream. */
  scan(prefix: string, options?: ScanOptions): AsyncIterable<Entry>;

  last(prefix: string): Promise<string | null>;

  /**
   * `put` for a key that must not already exist — false when it did, rather than
   * a throw. The same split Elasticsearch draws between `op_type=index` and
   * `op_type=create`.
   *
   * Mailbox ordinals are allocated by reading the tail and writing the next one,
   * which two concurrent deposits would both resolve to the same value — the
   * later write silently replacing the earlier deposit. Every backend worth
   * storing a witness in has a conditional write (`ON CONFLICT DO NOTHING`, a
   * versionstamp check, `attribute_not_exists`), so this is not optional: a
   * store with one writer simply never loses the race.
   */
  create(key: string, value: string): Promise<boolean>;
}
