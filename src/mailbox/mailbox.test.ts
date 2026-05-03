import assert from "node:assert";
import { basename } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, test } from "node:test";
import type { Message } from "#keri/cesr";
import { generateKeyPair, keri } from "#keri/core";
import { NodeSqliteDatabase, SqliteControllerStorage } from "#keri/storage/sqlite";
import { Mailbox } from "./mailbox.ts";

function makeMailbox() {
  return new Mailbox({
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
  });
}

function makeInnerMessage() {
  const { publicKey } = generateKeyPair();
  return keri.incept({ signingKeys: [publicKey], nextKeys: [] });
}

function makeForward(pre: string, topic: string, inner: Message) {
  const { publicKey: senderPub } = generateKeyPair();
  const sender = keri.incept({ signingKeys: [senderPub], nextKeys: [] });
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
  describe("handleMessage()", () => {
    test("should be a no-op for unknown message types", async () => {
      const mailbox = makeMailbox();
      const icp = makeInnerMessage();
      const replies = await Array.fromAsync(mailbox.handleMessage(icp));
      assert.strictEqual(replies.length, 0);
    });

    describe("/fwd", () => {
      test("should store the inner evt message", async () => {
        const mailbox = makeMailbox();
        const inner = makeInnerMessage();
        const fwd = makeForward("recipient-prefix", "credential", inner);

        await Array.fromAsync(mailbox.handleMessage(fwd));

        const query = makeQuery("recipient-prefix", { "/credential": 0 });
        const results = await Array.fromAsync(mailbox.handleMessage(query));

        assert.strictEqual(results.length, 1);
        assert.strictEqual(results[0].topic, "/credential");
        assert.strictEqual(results[0].message.body.t, inner.body.t);
        assert.strictEqual(results[0].message.body.d, inner.body.d);
      });

      test("should be a no-op when pre is missing", async () => {
        const mailbox = makeMailbox();
        const { publicKey: senderPub } = generateKeyPair();
        const sender = keri.incept({ signingKeys: [senderPub], nextKeys: [] });
        const inner = makeInnerMessage();

        const fwd = keri.exchange({
          sender: sender.body.i,
          route: "/fwd",
          query: { topic: "credential" },
          anchor: {},
          embeds: { evt: inner },
        });

        await Array.fromAsync(mailbox.handleMessage(fwd));

        const query = makeQuery("any-prefix", { "/credential": 0 });
        const results = await Array.fromAsync(mailbox.handleMessage(query));
        assert.strictEqual(results.length, 0);
      });
    });

    describe("mbx query", () => {
      test("should return empty for unknown recipient", async () => {
        const mailbox = makeMailbox();
        const query = makeQuery("unknown-prefix", { "/credential": 0 });
        const results = await Array.fromAsync(mailbox.handleMessage(query));
        assert.strictEqual(results.length, 0);
      });

      test("should return messages from the given offset", async () => {
        const mailbox = makeMailbox();
        const pre = "test-recipient";

        const msg1 = makeInnerMessage();
        const msg2 = makeInnerMessage();
        const msg3 = makeInnerMessage();

        await Array.fromAsync(mailbox.handleMessage(makeForward(pre, "credential", msg1)));
        await Array.fromAsync(mailbox.handleMessage(makeForward(pre, "credential", msg2)));
        await Array.fromAsync(mailbox.handleMessage(makeForward(pre, "credential", msg3)));

        const all = await Array.fromAsync(mailbox.handleMessage(makeQuery(pre, { "/credential": 0 })));
        assert.strictEqual(all.length, 3);

        const fromOffset = await Array.fromAsync(mailbox.handleMessage(makeQuery(pre, { "/credential": 1 })));
        assert.strictEqual(fromOffset.length, 2);
        assert.strictEqual(fromOffset[0].message.body.d, msg2.body.d);
        assert.strictEqual(fromOffset[1].message.body.d, msg3.body.d);
      });

      test("should scope messages by topic", async () => {
        const mailbox = makeMailbox();
        const pre = "test-recipient";

        await Array.fromAsync(mailbox.handleMessage(makeForward(pre, "credential", makeInnerMessage())));
        await Array.fromAsync(mailbox.handleMessage(makeForward(pre, "multisig", makeInnerMessage())));

        const credentials = await Array.fromAsync(mailbox.handleMessage(makeQuery(pre, { "/credential": 0 })));
        assert.strictEqual(credentials.length, 1);

        const multisig = await Array.fromAsync(mailbox.handleMessage(makeQuery(pre, { "/multisig": 0 })));
        assert.strictEqual(multisig.length, 1);
      });
    });
  });
});
