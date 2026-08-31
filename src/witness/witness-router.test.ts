import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { signRaw } from "../../test_utils/signing.ts";
import { Attachments, encodeText, Matter, type Message, parse } from "../cesr/main.ts";
import { generateKeyPair, type InceptEventBody, KeyEvent } from "../main.ts";
import { MemoryStore } from "./memory-store.ts";
import { Witness } from "./witness.ts";

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
  return new Witness({
    privateKey: generateKeyPair().privateKey,
    url: "http://localhost:5631",
    store: new MemoryStore(),
  });
}

class TestContext {
  readonly witness = makeWitness();
  readonly fetch = this.witness.fetch;
  icp: Message<InceptEventBody>;
  sigs: string[];

  constructor() {
    this.icp = KeyEvent.incept({
      signingKeys: [pubKey0],
      nextKeyDigests: [pubKey1],
      backers: [this.witness.aid],
    });
    this.sigs = [signRaw(this.icp.raw, privateKey0, 0)];
  }

  async receipt(event: Message<InceptEventBody>, sigs: string[]): Promise<Response> {
    return this.fetch(
      request("/receipts", {
        method: "POST",
        body: new TextDecoder().decode(event.raw),
        headers: {
          "Content-Type": "application/json",
          "CESR-ATTACHMENT": encodeText(new Attachments({ ControllerIdxSigs: sigs }).frames()),
        },
      }),
    );
  }
}

const { privateKey: privateKey0, publicKey: pubKey0 } = generateKeyPair();
const { publicKey: pubKey1 } = generateKeyPair();

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
          body: new TextDecoder().decode(context.icp.raw),
          headers: { "Content-Type": "application/json" },
        }),
      );
      assert.strictEqual(response.status, 400);
    });

    test("should return 200 for a valid rct message", async () => {
      const context = new TestContext();
      await context.receipt(context.icp, context.sigs);

      const rct = KeyEvent.receipt(context.icp);
      const rctAtc = new Attachments({ NonTransReceiptCouples: [] });

      const response = await context.fetch(
        request("/", {
          method: "POST",
          body: new TextDecoder().decode(rct.raw),
          headers: { "CESR-ATTACHMENT": encodeText(rctAtc.frames()) },
        }),
      );

      assert.strictEqual(response.status, 200);
    });

    test("should merge witness receipt signatures into stored event", async () => {
      const context1 = new TestContext();
      const context2 = new TestContext();

      const icpWithWitnesses = KeyEvent.incept({
        signingKeys: [pubKey0],
        nextKeyDigests: [pubKey1],
        backers: [context1.witness.aid, context2.witness.aid],
        backerThreshold: 1,
      });
      const icpSigs = [signRaw(icpWithWitnesses.raw, privateKey0, 0)];

      await context1.receipt(icpWithWitnesses, icpSigs);
      const rctResponse = await context2.receipt(icpWithWitnesses, icpSigs);
      const [rctMessage] = await collect(rctResponse.body);

      const rct = KeyEvent.receipt(icpWithWitnesses);
      const rctAtc = new Attachments({
        NonTransReceiptCouples: rctMessage.attachments.NonTransReceiptCouples,
      });

      const response = await context1.fetch(
        request("/", {
          method: "POST",
          body: new TextDecoder().decode(rct.raw),
          headers: { "CESR-ATTACHMENT": encodeText(rctAtc.frames()) },
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

      const response = await context.receipt(context.icp, context.sigs);

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");
    });

    test("should reply with valid witness receipt", async () => {
      const context = new TestContext();
      const response = await context.receipt(context.icp, context.sigs);

      const messages = await collect(response.body);

      assert(messages.length > 0);
      assert.strictEqual(messages[0].body.t, "rct");
      assert.strictEqual(messages[0].body.d, context.icp.body.d);

      const couples = messages[0].attachments.NonTransReceiptCouples;
      assert.strictEqual(couples.length, 1);

      const couple = couples[0];
      const sigMatter = Matter.parse(couple.sig);
      const keyMatter = Matter.parse(couple.prefix);
      assert(ed25519.verify(sigMatter.raw, context.icp.raw, keyMatter.raw));
    });

    test("should respond on oobi request for the new identifier", async () => {
      const context = new TestContext();
      await context.receipt(context.icp, context.sigs);
      const oobiResponse = await context.fetch(request(`/oobi/${context.icp.body.i}`, { method: "GET" }));
      assert.strictEqual(oobiResponse.status, 200);
      assert.strictEqual(oobiResponse.headers.get("Content-Type"), "application/json+cesr");

      const messages = await collect(oobiResponse.body);

      assert(messages.length > 0);
      assert.partialDeepStrictEqual(messages[0].body, {
        t: "icp",
        i: context.icp.body.i,
        s: "0",
      });

      assert.strictEqual(messages[0].attachments.ControllerIdxSigs.length, 1);
    });
  });
});
