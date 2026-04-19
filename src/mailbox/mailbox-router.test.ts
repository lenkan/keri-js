import assert from "node:assert";
import { basename } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, test } from "node:test";
import { Attachments, encodeText, parse } from "#keri/cesr";
import type { Message } from "#keri/core";
import { generateKeyPair, keri } from "#keri/core";
import { NodeSqliteDatabase, SqliteControllerStorage } from "#keri/storage/sqlite";
import { Mailbox } from "./mailbox.ts";
import { createRouter } from "./mailbox-router.ts";

function makeMailbox() {
  return new Mailbox({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
  });
}

function makeApp() {
  return createRouter(makeMailbox());
}

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`http://localhost${path}`, init);
}

async function parseSse(response: Response): Promise<Message[]> {
  const text = await response.text();
  for (const line of text.split("\n")) {
    if (line.startsWith("data: ")) {
      return Array.fromAsync(parse(line.slice(6)));
    }
  }
  return [];
}

function postMessage(message: Message): Request {
  const atc = new Attachments({
    ControllerIdxSigs: message.attachments.ControllerIdxSigs,
    TransIdxSigGroups: message.attachments.TransIdxSigGroups,
    TransLastIdxSigGroups: message.attachments.TransLastIdxSigGroups,
    PathedMaterialCouples: message.attachments.PathedMaterialCouples,
  });

  return request("/", {
    method: "POST",
    body: new TextDecoder().decode(message.raw),
    headers: { "CESR-ATTACHMENT": encodeText(atc.frames()) },
  });
}

function makeForward(pre: string, topic: string) {
  const { publicKey: senderPub } = generateKeyPair();
  const sender = keri.incept({ signingKeys: [senderPub], nextKeys: [] });
  const { publicKey: innerPub } = generateKeyPair();
  const inner = keri.incept({ signingKeys: [innerPub], nextKeys: [] });
  return keri.exchange({
    sender: sender.body.i,
    route: "/fwd",
    query: { pre, topic },
    anchor: {},
    embeds: { evt: inner },
  });
}

function makeQuery(id: string, topics: Record<string, number>) {
  return keri.query({ r: "mbx", q: { i: id, topics } });
}

describe(basename(import.meta.url), () => {
  describe("GET /", () => {
    test("should return 200 with status ok", async () => {
      const app = makeApp();
      const response = await app(request("/", { method: "GET" }));
      assert.strictEqual(response.status, 200);
      assert.deepStrictEqual(await response.json(), { status: "OK" });
    });
  });

  describe("POST /", () => {
    test("should return 400 when CESR-ATTACHMENT header is missing", async () => {
      const app = makeApp();
      const { publicKey } = generateKeyPair();
      const icp = keri.incept({ signingKeys: [publicKey], nextKeys: [] });
      const response = await app(
        request("/", {
          method: "POST",
          body: new TextDecoder().decode(icp.raw),
        }),
      );
      assert.strictEqual(response.status, 400);
    });

    test("should return 204 when no reply messages are produced", async () => {
      const app = makeApp();
      const { publicKey } = generateKeyPair();
      const icp = keri.incept({ signingKeys: [publicKey], nextKeys: [] });
      const response = await app(postMessage(icp));
      assert.strictEqual(response.status, 204);
    });

    test("should return 204 for a /fwd message (store only, no reply)", async () => {
      const app = makeApp();
      const fwd = makeForward("some-recipient", "credential");
      const response = await app(postMessage(fwd));
      assert.strictEqual(response.status, 204);
    });

    test("should return 204 for a mbx query when mailbox is empty", async () => {
      const app = makeApp();
      const query = makeQuery("unknown-prefix", { "/credential": 0 });
      const response = await app(postMessage(query));
      assert.strictEqual(response.status, 204);
    });

    test("should return stored messages as text/event-stream on mbx query", async () => {
      const app = createRouter(makeMailbox());
      const pre = "test-recipient";

      await app(postMessage(makeForward(pre, "credential")));
      await app(postMessage(makeForward(pre, "credential")));

      const response = await app(postMessage(makeQuery(pre, { "/credential": 0 })));

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.headers.get("Content-Type"), "text/event-stream");

      const messages = await parseSse(response);
      assert.strictEqual(messages.length, 2);
      assert.strictEqual(messages[0].body.t, "icp");
      assert.strictEqual(messages[1].body.t, "icp");
    });

    test("should respect offset in mbx query", async () => {
      const app = createRouter(makeMailbox());
      const pre = "test-recipient";

      await app(postMessage(makeForward(pre, "credential")));
      await app(postMessage(makeForward(pre, "credential")));
      await app(postMessage(makeForward(pre, "credential")));

      const response = await app(postMessage(makeQuery(pre, { "/credential": 1 })));
      const messages = await parseSse(response);
      assert.strictEqual(messages.length, 2);
    });
  });

  describe("unknown routes", () => {
    test("should return 404 for unknown path", async () => {
      const app = makeApp();
      const response = await app(request("/unknown", { method: "GET" }));
      assert.strictEqual(response.status, 404);
    });

    test("should return 405 for unsupported method", async () => {
      const app = makeApp();
      const response = await app(request("/", { method: "DELETE" }));
      assert.strictEqual(response.status, 405);
    });
  });
});
