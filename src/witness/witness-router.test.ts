import assert from "node:assert";
import { basename } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Attachments, Indexer, Matter } from "../cesr/__main__.ts";
import { generateKeyPair } from "../core/keys.ts";
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
    privateKey: generateKeyPair().privateKey,
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

const { privateKey: privateKey0, publicKey: pubKey0 } = generateKeyPair();
const { publicKey: pubKey1 } = generateKeyPair();

const icp = keri.incept({
  signingKeys: [pubKey0],
  nextKeys: [pubKey1],
});

const sigs = [Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey0), 0).text()];

describe(basename(import.meta.url), () => {
  describe("oobi request", () => {
    test("should reply with status 200", async () => {
      const context = new TestContext();
      const response = await context.fetch(request("/oobi", { method: "GET" }));
      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");

      assert(response.body);
    });

    test("should reply with incept event", async () => {
      const context = new TestContext();
      const response = await context.fetch(request("/oobi", { method: "GET" }));
      assert(response.body);
      const messages = await collect(parseKeyEvents(response.body));

      assert(messages.length > 0);
      assert.strictEqual(messages[0].message.body.t, "icp");
      assert.strictEqual(messages[0].message.body.i, context.witness.aid);
    });

    test("should reply with location record", async () => {
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

    test("should reply with end role", async () => {
      const context = new TestContext();
      const response = await context.fetch(request("/oobi", { method: "GET" }));
      assert(response.body);
      const messages = await collect(parseKeyEvents(response.body));

      const message = messages.find((m) => m.message.body.r === "/end/role/add");
      assert.strictEqual(message?.message.body.t, "rpy");
      assert.strictEqual(message?.message.body.r, "/end/role/add");
    });
  });

  describe("message request", () => {
    test("should return 400 when CESR-ATTACHMENT header is missing", async () => {
      const context = new TestContext();
      const response = await context.fetch(
        request("/", {
          method: "POST",
          body: new TextDecoder().decode(icp.raw),
          headers: { "Content-Type": "application/json" },
        }),
      );
      assert.strictEqual(response.status, 400);
    });

    test("should return 200 for a valid rct message", async () => {
      const context = new TestContext();
      await context.receipt(icp, sigs);

      const rct = keri.receipt({ d: icp.body.d, i: icp.body.i, s: "0" });
      const rctAtc = new Attachments({ NonTransReceiptCouples: [] });

      const response = await context.fetch(
        request("/", {
          method: "POST",
          body: new TextDecoder().decode(rct.raw),
          headers: { "CESR-ATTACHMENT": rctAtc.text() },
        }),
      );

      assert.strictEqual(response.status, 200);
    });

    test("should merge witness receipt signatures into stored event", async () => {
      const context1 = new TestContext();
      const context2 = new TestContext();

      const icpWithWitnesses = keri.incept({
        signingKeys: [pubKey0],
        nextKeys: [pubKey1],
        wits: [context1.witness.aid, context2.witness.aid],
        toad: 1,
      });
      const icpSigs = [Indexer.crypto.ed25519_sig(ed25519.sign(icpWithWitnesses.raw, privateKey0), 0).text()];

      await context1.receipt(icpWithWitnesses, icpSigs);
      const rctResponse = await context2.receipt(icpWithWitnesses, icpSigs);
      assert(rctResponse.body);
      const [rctMessage] = await collect(parseKeyEvents(rctResponse.body));

      const rct = keri.receipt({ d: icpWithWitnesses.body.d, i: icpWithWitnesses.body.i, s: "0" });
      const rctAtc = new Attachments({
        NonTransReceiptCouples: rctMessage.message.attachments.NonTransReceiptCouples,
      });

      const response = await context1.fetch(
        request("/", {
          method: "POST",
          body: new TextDecoder().decode(rct.raw),
          headers: { "CESR-ATTACHMENT": rctAtc.text() },
        }),
      );

      assert.strictEqual(response.status, 200);

      const oobiResponse = await context1.fetch(request(`/oobi/${icpWithWitnesses.body.i}`, { method: "GET" }));
      assert(oobiResponse.body);
      const messages = await collect(parseKeyEvents(oobiResponse.body));
      assert(messages.length > 0);
      assert.strictEqual(messages[0].message.attachments.WitnessIdxSigs.length, 2);
    });
  });

  describe("receipt request", () => {
    test("should reply with valid http response", async () => {
      const context = new TestContext();

      const response = await context.receipt(icp, sigs);

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");
    });

    test("should reply with valid witness receipt", async () => {
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

    test("should respond on oobi request for the new identifier", async () => {
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
});
