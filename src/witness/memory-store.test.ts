import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { MemoryStore } from "./memory-store.ts";

async function seeded(...keys: string[]): Promise<MemoryStore> {
  const store = new MemoryStore();
  for (const key of keys) {
    await store.put(key, key);
  }
  return store;
}

const keys = async (store: MemoryStore, prefix: string, options?: { start?: string; limit?: number }) =>
  (await Array.fromAsync(store.scan(prefix, options))).map((entry) => entry.key);

describe(basename(import.meta.url), () => {
  test("should return null for a key that was never written", async () => {
    assert.strictEqual(await new MemoryStore().get("nothing"), null);
  });

  test("should overwrite on put and drop on delete", async () => {
    const store = new MemoryStore();
    await store.put("k", "one");
    await store.put("k", "two");
    assert.strictEqual(await store.get("k"), "two");

    await store.delete("k");
    assert.strictEqual(await store.get("k"), null);
  });

  test("should scan a prefix in ascending key order", async () => {
    const store = await seeded("a:2", "a:0", "a:1");
    assert.deepStrictEqual(await keys(store, "a:"), ["a:0", "a:1", "a:2"]);
  });

  test("should exclude keys outside the prefix", async () => {
    const store = await seeded("a:0", "ab:0", "b:0");
    assert.deepStrictEqual(await keys(store, "a:"), ["a:0"]);
  });

  test("should treat scan start as an inclusive lower bound", async () => {
    const store = await seeded("a:0", "a:1", "a:2");
    assert.deepStrictEqual(await keys(store, "a:", { start: "a:1" }), ["a:1", "a:2"]);
  });

  test("should cap a scan at the limit, counting from the start bound", async () => {
    const store = await seeded("a:0", "a:1", "a:2", "a:3");
    assert.deepStrictEqual(await keys(store, "a:", { start: "a:1", limit: 2 }), ["a:1", "a:2"]);
  });

  test("should report the greatest key under a prefix", async () => {
    const store = await seeded("a:0", "a:2", "a:1", "b:9");
    assert.strictEqual(await store.last("a:"), "a:2");
    assert.strictEqual(await store.last("c:"), null);
  });

  test("should write on create only while the key is free", async () => {
    const store = new MemoryStore();

    assert.strictEqual(await store.create("k", "first"), true);
    assert.strictEqual(await store.create("k", "second"), false);
    assert.strictEqual(await store.get("k"), "first");
  });
});
