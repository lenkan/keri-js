import { before, beforeEach, describe, test } from "node:test";
import assert from "node:assert";
import { scrypt } from "@noble/hashes/scrypt.js";
import { Witness } from "./witness.ts";
import { parseKeyEvents } from "./client.ts";
import { type InceptEvent, keri } from "./events/events.ts";
import { type Key, KeyManager, verify } from "./keystore/key-manager.ts";
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

let witness: Witness;

beforeEach(async () => {
  witness = new Witness({
    seed: createSeed("witness"),
    url: "http://localhost:5631",
  });
});

describe("Witness oobi request", () => {
  let response: Response;

  beforeEach(async () => {
    response = await witness.fetch(request("/oobi", { method: "GET" }));
  });

  test("Should reply status 200", async () => {
    assert.strictEqual(response.status, 200);
  });

  test("Should reply with correct content type", async () => {
    assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");
  });

  test("Should reply with witness inception event", async () => {
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    assert(messages.length > 0);
    assert.strictEqual(messages[0].event.t, "icp");
    assert.strictEqual(messages[0].event.i, "BJi2Gy-mghF6uHwdq_9ZJvpmYm05xvWRW2hGJvD_yk3S");
  });

  test("Should reply with location record", async () => {
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    const message = messages.find((m) => m.event.r === "/loc/scheme");
    assert.partialDeepStrictEqual(message?.event, {
      t: "rpy",
      r: "/loc/scheme",
    });
  });

  test("Should reply with end role", async () => {
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    const message = messages.find((m) => m.event.r === "/end/role/add");
    assert.strictEqual(message?.event.t, "rpy");
    assert.strictEqual(message?.event.r, "/end/role/add");
  });
});

describe("Witness receipt request", () => {
  let key: Key;
  let icp: InceptEvent;
  let response: Response;

  before(async () => {
    key = await keys.import(
      ed25519.utils.randomSecretKey(createSeed("0")),
      ed25519.utils.randomSecretKey(createSeed("1")),
    );

    icp = keri.incept({
      k: [key.current],
      n: [key.next],
    });
  });

  beforeEach(async () => {
    response = await witness.fetch(
      request("/receipts", {
        method: "POST",
        body: JSON.stringify(icp),
      }),
    );
  });

  test("Should reply with valid http response", async () => {
    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");
  });

  test("Should reply with valid witness receipt", async () => {
    assert(response.body);
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

  test("Should respond on oobi request for the new identifier", async () => {
    const response = await witness.fetch(request(`/oobi/${icp.i}`, { method: "GET" }));
    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");

    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    assert(messages.length > 0);
    assert.partialDeepStrictEqual(messages[0].event, {
      t: "icp",
      i: icp.i,
      s: "0",
    });
  });
});
