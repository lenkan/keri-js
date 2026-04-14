import assert from "node:assert";
import { DatabaseSync } from "node:sqlite";
import { describe, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Attachments, Indexer, Matter, Message } from "../cesr/__main__.ts";
import { type InceptEventBody, type KeyEvent, keri } from "../core/main.ts";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../storage/sqlite/storage-sqlite.ts";
import { parseKeyEvents } from "./parser.ts";
import { createSeed } from "./seed.ts";
import { Witness, WitnessError } from "./witness.ts";
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
    privateKey: ed25519.utils.randomSecretKey(createSeed("witness", "salt")),
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

// --- Shared test fixtures ---

const privateKey0 = ed25519.utils.randomSecretKey(createSeed("0", "salt"));
const privateKey1 = ed25519.utils.randomSecretKey(createSeed("1", "salt"));

const pubKey0 = new Matter({ code: Matter.Code.Ed25519, raw: ed25519.getPublicKey(privateKey0) }).text();
const pubKey1 = new Matter({ code: Matter.Code.Ed25519, raw: ed25519.getPublicKey(privateKey1) }).text();

const icp = keri.incept({
  signingKeys: [pubKey0],
  nextKeys: [pubKey1],
});

const sigs = [Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, privateKey0), 0).text()];

// --- Witness unit tests ---

describe("Witness", () => {
  test("receive() returns a valid RCT message", () => {
    const witness = makeWitness();
    const msg = new Message(icp.body, { ControllerIdxSigs: sigs });

    const receipt = witness.receive(msg);

    assert.strictEqual(receipt.body.t, "rct");
    assert.strictEqual(receipt.body.d, icp.body.d);

    const couples = receipt.attachments.NonTransReceiptCouples;
    assert.strictEqual(couples.length, 1);
    assert.strictEqual(couples[0].prefix, witness.aid);

    const sigMatter = Matter.parse(couples[0].sig);
    const keyMatter = Matter.parse(couples[0].prefix);
    assert(ed25519.verify(sigMatter.raw, msg.raw, keyMatter.raw));
  });

  test("receive() stores the event so getKeyEvents returns it", () => {
    const witness = makeWitness();
    const msg = new Message(icp.body, { ControllerIdxSigs: sigs });

    witness.receive(msg);

    const stored = Array.from(witness.getKeyEvents(icp.body.i));
    assert.strictEqual(stored.length, 1);
    assert.strictEqual(stored[0].body.t, "icp");
    assert.strictEqual((stored[0].body as InceptEventBody).i, icp.body.i);
  });

  test("receive() throws WitnessError when controller signatures are missing", () => {
    const witness = makeWitness();
    const msg = new Message(icp.body, { ControllerIdxSigs: [] });

    assert.throws(() => witness.receive(msg), WitnessError);
  });

  test("getKeyEvents() returns empty for unknown AID", () => {
    const witness = makeWitness();
    const stored = Array.from(witness.getKeyEvents("unknown-aid"));
    assert.strictEqual(stored.length, 0);
  });
});

// --- HTTP layer tests ---

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
