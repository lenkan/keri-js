import assert from "node:assert";
import { before, beforeEach, describe, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Attachments, Indexer, Matter } from "cesr";
import type { Hono } from "hono";
import { type InceptEvent, type KeyEvent, keri } from "keri";
import { createApp } from "./app.ts";
import { createTable } from "./dynamo-client.ts";
import { EventStorage } from "./event-storage.ts";
import { parseKeyEvents } from "./parser.ts";
import { createSeed } from "./seed.ts";
import { createWitness, type Witness } from "./witness.ts";

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

let app: Hono;
let witness: Witness;

beforeEach(async () => {
  const endpoint = "http://admin:password@localhost:8000";
  const tableName = `test_events_${crypto.randomUUID()}`;
  const client = await createTable(tableName, endpoint);

  witness = createWitness({
    privateKey: ed25519.utils.randomSecretKey(createSeed("witness", "salt")),
    url: "http://localhost:5631",
  });

  app = createApp({
    witness,
    storage: new EventStorage({ tableName, client }),
  });
});

describe("Witness oobi request", () => {
  let response: Response;

  beforeEach(async () => {
    response = await app.fetch(request("/oobi", { method: "GET" }));
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
    assert.strictEqual(messages[0].message.body.t, "icp");
    assert.strictEqual(messages[0].message.body.i, witness.aid);
  });

  test("Should reply with location record", async () => {
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    const message = messages.find((m) => m.message.body.r === "/loc/scheme");
    assert.partialDeepStrictEqual(message?.message.body, {
      t: "rpy",
      r: "/loc/scheme",
    });
  });

  test("Should reply with end role", async () => {
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    const message = messages.find((m) => m.message.body.r === "/end/role/add");
    assert.strictEqual(message?.message.body.t, "rpy");
    assert.strictEqual(message?.message.body.r, "/end/role/add");
  });
});

describe("Witness receipt request", () => {
  let privateKey0: Uint8Array;
  let icp: KeyEvent<InceptEvent>;
  let response: Response;
  let sigs: string[];

  before(async () => {
    privateKey0 = ed25519.utils.randomSecretKey(createSeed("0", "salt"));
    const privateKey1 = ed25519.utils.randomSecretKey(createSeed("1", "salt"));

    const pubKey0 = new Matter({ code: Matter.Code.Ed25519, raw: ed25519.getPublicKey(privateKey0) }).text();
    const pubKey1 = new Matter({ code: Matter.Code.Ed25519, raw: ed25519.getPublicKey(privateKey1) }).text();

    icp = keri.incept({
      signingKeys: [pubKey0],
      nextKeys: [pubKey1],
    });

    sigs = [Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey0), 0).text()];
  });

  beforeEach(async () => {
    response = await app.fetch(
      request("/receipts", {
        method: "POST",
        body: new TextDecoder().decode(icp.raw),
        headers: {
          "Content-Type": "application/json",
          "CESR-ATTACHMENT": new Attachments({ ControllerIdxSigs: sigs }).text(),
        },
      }),
    );

    assert.strictEqual(response.status, 200);
  });

  test("Should reply with valid http response", async () => {
    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");
  });

  test("Should reply with valid witness receipt", async () => {
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    assert(messages.length > 0);
    assert.strictEqual(messages[0].message.body.t, "rct");
    assert.strictEqual(messages[0].message.body.d, icp.body.d);

    const couples = messages[0].message.attachments.NonTransReceiptCouples;
    assert.strictEqual(couples.length, 1);

    const couple = couples[0];
    const sigMatter = Matter.parse(couple.sig);
    const keyMatter = Matter.parse(couple.prefix);
    assert(ed25519.verify(sigMatter.raw, icp.raw, keyMatter.raw));
  });

  test("Should respond on oobi request for the new identifier", async () => {
    const oobiResponse = await app.fetch(request(`/oobi/${icp.body.i}`, { method: "GET" }));
    assert.strictEqual(oobiResponse.status, 200);
    assert.strictEqual(oobiResponse.headers.get("Content-Type"), "application/json+cesr");

    assert(oobiResponse.body);
    const messages = await collect(parseKeyEvents(oobiResponse.body));

    assert(messages.length > 0);
    assert.partialDeepStrictEqual(messages[0].message.body, {
      t: "icp",
      i: icp.body.i,
      s: "0",
    });

    assert.strictEqual(messages[0].message.attachments.ControllerIdxSigs.length, 1);
  });
});
