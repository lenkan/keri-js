import type { Entry, ScanOptions, Store } from "./store.ts";

/**
 * A `Store` held in a `Map`, for tests and for trying a witness out. Nothing
 * survives the process, and a witness that loses its stored KEL stops being able
 * to prove what it receipted, so back a real deployment with something durable.
 *
 * `scan` sorts the whole key set per call rather than keeping an ordered index:
 * the sizes this is meant for do not notice, and the sizes that would are the
 * ones that should not be using it.
 */
export class MemoryStore implements Store {
  readonly #entries = new Map<string, string>();

  async get(key: string): Promise<string | null> {
    return this.#entries.get(key) ?? null;
  }

  async put(key: string, value: string): Promise<void> {
    this.#entries.set(key, value);
  }

  async create(key: string, value: string): Promise<boolean> {
    if (this.#entries.has(key)) {
      return false;
    }
    this.#entries.set(key, value);
    return true;
  }

  async delete(key: string): Promise<void> {
    this.#entries.delete(key);
  }

  async *scan(prefix: string, options: ScanOptions = {}): AsyncIterable<Entry> {
    const start = options.start ?? prefix;
    const keys = Array.from(this.#entries.keys())
      .filter((key) => key.startsWith(prefix) && key >= start)
      .sort();

    const limit = options.limit ?? keys.length;
    for (const key of keys.slice(0, limit)) {
      yield { key, value: this.#entries.get(key) as string };
    }
  }

  async last(prefix: string): Promise<string | null> {
    let last: string | null = null;
    for (const key of this.#entries.keys()) {
      if (key.startsWith(prefix) && (last === null || key > last)) {
        last = key;
      }
    }
    return last;
  }
}
