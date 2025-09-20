import { describe, test } from "node:test";
import assert from "node:assert";
import { scrypt } from "@noble/hashes/scrypt.js";
import { Witness } from "./witness.ts";
import { parseKeyEvents } from "./client.ts";
import { keri } from "./events/events.ts";
import { KeyManager, verify } from "./keystore/key-manager.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { MapStore } from "./db/storage.ts";

function createSeed(init: string): Uint8Array {
  return scrypt(init, "salt", { N: 16384, r: 8, p: 1, dkLen: 32 });
}

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`http://localhost${path}`, init);
}

async function collect<T>(iter: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const item of iter) {
    result.push(item);
  }
  return result;
}

const keys = new KeyManager({
  storage: new MapStore(),
  encrypter: { decrypt: async (x) => x, encrypt: async (x) => x },
});

const witness = new Witness({ seed: createSeed("witness") });

describe("Witness oobi request", () => {
  test("Should reply with witness inception stream", async () => {
    const response = await witness.fetch(request("/oobi", { method: "GET" }));

    assert(response.status === 200);
    assert(response.body);
    assert.strictEqual(response.headers.get("Content-Type"), "application/cesr+json");

    const messages = await collect(parseKeyEvents(response.body));

    assert(messages.length > 0);
    assert.strictEqual(messages[0].event.t, "icp");
    assert.strictEqual(messages[0].event.i, "BJi2Gy-mghF6uHwdq_9ZJvpmYm05xvWRW2hGJvD_yk3S");
  });
});

describe("Witness receipt request", () => {
  test("Should reply with valid witness receipt", async () => {
    const key = await keys.import(
      ed25519.utils.randomSecretKey(createSeed("0")),
      ed25519.utils.randomSecretKey(createSeed("1")),
    );

    const icp = keri.incept({
      k: [key.current],
      n: [key.next],
    });

    const response = await witness.fetch(
      request("/receipts", {
        method: "POST",
        body: JSON.stringify(icp),
      }),
    );

    assert(response.status === 200);
    assert(response.body);
    assert.strictEqual(response.headers.get("Content-Type"), "application/cesr+json");

    const messages = await collect(parseKeyEvents(response.body));

    assert(messages.length > 0);
    assert.strictEqual(messages[0].event.t, "rct");
    assert.strictEqual(messages[0].event.d, icp.d);
    assert.strictEqual(messages[0].event.i, "EAR0p0ULWUwU96OIqmHSMusuWx3Ut6poFkC8pNe6QfYX");
    assert.strictEqual(messages[0].receipts.length, 1);

    const receipt = messages[0].receipts[0];
    const payload = new TextEncoder().encode(JSON.stringify(icp));
    assert(verify(receipt.backer, payload, receipt.signature));
  });
});
