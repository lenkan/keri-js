import assert from "node:assert";
import { basename } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Attachments, Indexer, Matter, type Message, parse } from "#keri/cesr";
import { generateKeyPair, type InceptEventBody, type KeyEvent, keri } from "#keri/core";
import { NodeSqliteDatabase, SqliteControllerStorage } from "#keri/storage/sqlite";
import { Witness } from "./witness.ts";
import { createRouter } from "./witness-router.ts";

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`http://localhost${path}`, init);
}

async function collect(stream: ReadableStream<Uint8Array> | null): Promise<Message[]> {
  const result: Message[] = [];
  for await (const message of parse(stream ?? new Uint8Array())) {
    result.push(message);
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
    });

    test("should reply with incept event", async () => {
      const context = new TestContext();
      const response = await context.fetch(request("/oobi", { method: "GET" }));
      const messages = await collect(response.body);

      assert(messages.length > 0);
      assert.strictEqual(messages[0].body.t, "icp");
      assert.strictEqual(messages[0].body.i, context.witness.aid);
    });

    test("should reply with location record", async () => {
      const context = new TestContext();
      const response = await context.fetch(request("/oobi", { method: "GET" }));
      const messages = await collect(response.body);

      const message = messages.find((m) => m.body.r === "/loc/scheme");
      assert.partialDeepStrictEqual(message?.body, {
        t: "rpy",
        r: "/loc/scheme",
      });
    });

    test("should reply with end role", async () => {
      const context = new TestContext();
      const response = await context.fetch(request("/oobi", { method: "GET" }));

      const messages = await collect(response.body);

      const message = messages.find((m) => m.body.r === "/end/role/add");
      assert.strictEqual(message?.body.t, "rpy");
      assert.strictEqual(message?.body.r, "/end/role/add");
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
      const [rctMessage] = await collect(rctResponse.body);

      const rct = keri.receipt({ d: icpWithWitnesses.body.d, i: icpWithWitnesses.body.i, s: "0" });
      const rctAtc = new Attachments({
        NonTransReceiptCouples: rctMessage.attachments.NonTransReceiptCouples,
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
      const messages = await collect(oobiResponse.body);
      assert(messages.length > 0);
      assert.strictEqual(messages[0].attachments.WitnessIdxSigs.length, 2);
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

      const messages = await collect(response.body);

      assert(messages.length > 0);
      assert.strictEqual(messages[0].body.t, "rct");
      assert.strictEqual(messages[0].body.d, icp.body.d);

      const couples = messages[0].attachments.NonTransReceiptCouples;
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

      const messages = await collect(oobiResponse.body);

      assert(messages.length > 0);
      assert.partialDeepStrictEqual(messages[0].body, {
        t: "icp",
        i: icp.body.i,
        s: "0",
      });

      assert.strictEqual(messages[0].attachments.ControllerIdxSigs.length, 1);
    });
  });
});
