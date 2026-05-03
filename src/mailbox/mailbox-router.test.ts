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

function makeMailbox(url?: string) {
  return new Mailbox({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
    url,
  });
}

function makeApp(url?: string) {
  return createRouter(makeMailbox(url));
}

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`http://localhost${path}`, init);
}

async function parseSse(response: Response): Promise<Message[]> {
  const text = await response.text();
  const messages: Message[] = [];
  for (const line of text.split("\n")) {
    if (line.startsWith("data: ")) {
      messages.push(...(await Array.fromAsync(parse(line.slice(6)))));
    }
  }
  return messages;
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

  describe("GET /oobi", () => {
    test("should return 200 with application/json+cesr content type", async () => {
      const app = makeApp("http://localhost:5640");
      const response = await app(request("/oobi", { method: "GET" }));
      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.headers.get("Content-Type"), "application/json+cesr");
    });

    test("should include Keri-Aid header with mailbox AID", async () => {
      const mailbox = makeMailbox("http://localhost:5640");
      const app = createRouter(mailbox);
      const response = await app(request("/oobi", { method: "GET" }));
      assert.strictEqual(response.headers.get("Keri-Aid"), mailbox.aid);
    });

    test("should return inception event as first message", async () => {
      const mailbox = makeMailbox("http://localhost:5640");
      const app = createRouter(mailbox);
      const response = await app(request("/oobi", { method: "GET" }));
      const messages = await Array.fromAsync(parse(response.body ?? new Uint8Array()));
      assert(messages.length > 0);
      assert.strictEqual(messages[0].body.t, "icp");
      assert.strictEqual(messages[0].body.i, mailbox.aid);
    });

    test("should return location record", async () => {
      const app = makeApp("http://localhost:5640");
      const response = await app(request("/oobi", { method: "GET" }));
      const messages = await Array.fromAsync(parse(response.body ?? new Uint8Array()));
      const loc = messages.find((m) => m.body.r === "/loc/scheme");
      assert.partialDeepStrictEqual(loc?.body, { t: "rpy", r: "/loc/scheme" });
    });

    test("should return end role record with mailbox role", async () => {
      const app = makeApp("http://localhost:5640");
      const response = await app(request("/oobi", { method: "GET" }));
      const messages = await Array.fromAsync(parse(response.body ?? new Uint8Array()));
      const endrole = messages.find((m) => m.body.r === "/end/role/add");
      assert.partialDeepStrictEqual(endrole?.body, { t: "rpy", r: "/end/role/add" });
      assert.strictEqual((endrole?.body.a as { role?: string })?.role, "mailbox");
    });

    test("should return only inception event when no url is configured", async () => {
      const app = makeApp();
      const response = await app(request("/oobi", { method: "GET" }));
      const messages = await Array.fromAsync(parse(response.body ?? new Uint8Array()));
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].body.t, "icp");
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
