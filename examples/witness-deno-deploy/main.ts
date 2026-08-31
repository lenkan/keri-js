import { decodeBase64Url } from "keri/cesr";
import { type Entry, type ScanOptions, type Store, Witness } from "keri/witness";

/** The key one past the prefix, so a prefix scan is a `[start, end)` range. */
function rangeEnd(prefix: string): string {
  return prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
}

/**
 * Deno KV, which is async and replicated across regions — so there is no single
 * writer, and `create` is doing real work here rather than being a
 * formality. Without it two deposits landing at once would both read the same
 * mailbox tail and one would overwrite the other.
 *
 * Keys are one-element arrays holding the whole key string, so KV's ordering on
 * that part is the lexical ordering the witness relies on and a `start`/`end`
 * range is an exact prefix scan.
 */
class KvStore implements Store {
  readonly #kv: Deno.Kv;

  constructor(kv: Deno.Kv) {
    this.#kv = kv;
  }

  async get(key: string): Promise<string | null> {
    return (await this.#kv.get<string>([key])).value;
  }

  async put(key: string, value: string): Promise<void> {
    await this.#kv.set([key], value);
  }

  async create(key: string, value: string): Promise<boolean> {
    const result = await this.#kv
      .atomic()
      .check({ key: [key], versionstamp: null })
      .set([key], value)
      .commit();
    return result.ok;
  }

  async delete(key: string): Promise<void> {
    await this.#kv.delete([key]);
  }

  async *scan(prefix: string, options: ScanOptions = {}): AsyncIterable<Entry> {
    const selector = { start: [options.start ?? prefix], end: [rangeEnd(prefix)] };

    for await (const entry of this.#kv.list<string>(selector, { limit: options.limit })) {
      yield { key: entry.key[0] as string, value: entry.value };
    }
  }

  async last(prefix: string): Promise<string | null> {
    const selector = { start: [prefix], end: [rangeEnd(prefix)] };

    for await (const entry of this.#kv.list<string>(selector, { reverse: true, limit: 1 })) {
      return entry.key[0] as string;
    }
    return null;
  }
}

function required(name: string): string {
  const value = Deno.env.get(name);
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

const witnessUrl = required("WITNESS_URL");

const witness = new Witness({
  privateKey: decodeBase64Url(required("WITNESS_SEED")),
  url: witnessUrl,
  store: new KvStore(await Deno.openKv()),
});

console.log(`witness ${witness.aid}`);

// The port comes from the URL rather than its own variable, so the two cannot
// disagree — controllers dial whatever `/loc/scheme` says, and a witness
// listening somewhere else is simply unreachable. A deployed URL names no port,
// which leaves the choice to Deno Deploy.
const { port } = new URL(witnessUrl);
Deno.serve(port ? { port: Number(port) } : {}, witness.fetch);
