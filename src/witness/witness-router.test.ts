import assert from "node:assert";
import { DatabaseSync } from "node:sqlite";
import { describe, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Attachments, Indexer, Matter } from "../cesr/__main__.ts";
import { type InceptEventBody, type KeyEvent, keri } from "../core/main.ts";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../storage/sqlite/storage-sqlite.ts";
import { parseKeyEvents } from "./parser.ts";
import { Witness } from "./witness.ts";
import { createRouter } from "./witness-router.ts";

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

function makeWitness(): Witness {
  const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));
  return new Witness({
    privateKey: ed25519.utils.randomSecretKey(crypto.getRandomValues(new Uint8Array(32))),
    url: "http://localhost:5631",
    storage,
  });
}

class TestContext {
  app: (request: Request) => Promise<Response>;
  witness: Witness;

  constructor() {
    this.witness = makeWitness();
    this.app = createRouter(this.witness);
  }

  async fetch(input: Request): Promise<Response> {
    return this.app(input);
  }

  async receipt(event: KeyEvent<InceptEventBody>, sigs: string[]): Promise<Response> {
    const result = await this.fetch(
      request("/receipts", {
        method: "POST",
        body: new TextDecoder().decode(event.raw),
        headers: {
          "Content-Type": "application/json",
          "CESR-ATTACHMENT": new Attachments({ ControllerIdxSigs: sigs }).text(),
        },
      }),
    );

    return result;
  }
}

const privateKey0 = ed25519.utils.randomSecretKey(crypto.getRandomValues(new Uint8Array(32)));
const privateKey1 = ed25519.utils.randomSecretKey(crypto.getRandomValues(new Uint8Array(32)));

const pubKey0 = new Matter({ code: Matter.Code.Ed25519, raw: ed25519.getPublicKey(privateKey0) }).text();
const pubKey1 = new Matter({ code: Matter.Code.Ed25519, raw: ed25519.getPublicKey(privateKey1) }).text();

const icp = keri.incept({
  signingKeys: [pubKey0],
  nextKeys: [pubKey1],
});

const sigs = [Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey0), 0).text()];

describe("Witness oobi request", () => {
  test("Should reply status 200", async () => {
    const context = new TestContext();
    const response = await context.fetch(request("/oobi", { method: "GET" }));
    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");

    assert(response.body);
  });

  test("Should reply with incept event", async () => {
    const context = new TestContext();
    const response = await context.fetch(request("/oobi", { method: "GET" }));
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    assert(messages.length > 0);
    assert.strictEqual(messages[0].message.body.t, "icp");
    assert.strictEqual(messages[0].message.body.i, context.witness.aid);
  });

  test("Should reply with location record", async () => {
    const context = new TestContext();
    const response = await context.fetch(request("/oobi", { method: "GET" }));
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    const message = messages.find((m) => m.message.body.r === "/loc/scheme");
    assert.partialDeepStrictEqual(message?.message.body, {
      t: "rpy",
      r: "/loc/scheme",
    });
  });

  test("Should reply with end role", async () => {
    const context = new TestContext();
    const response = await context.fetch(request("/oobi", { method: "GET" }));
    assert(response.body);
    const messages = await collect(parseKeyEvents(response.body));

    const message = messages.find((m) => m.message.body.r === "/end/role/add");
    assert.strictEqual(message?.message.body.t, "rpy");
    assert.strictEqual(message?.message.body.r, "/end/role/add");
  });
});

describe("Witness receipt request", () => {
  test("Should reply with valid http response", async () => {
    const context = new TestContext();

    const response = await context.receipt(icp, sigs);

    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");
  });

  test("Should reply with valid witness receipt", async () => {
    const context = new TestContext();
    const response = await context.receipt(icp, sigs);

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
    const context = new TestContext();
    await context.receipt(icp, sigs);
    const oobiResponse = await context.fetch(request(`/oobi/${icp.body.i}`, { method: "GET" }));
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
