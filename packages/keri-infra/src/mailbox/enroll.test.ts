import assert from "node:assert";
import { basename } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, type Message, parse } from "cesr";
import type { KeyPair, ReplyEventBody } from "keri";
import { generateKeyPair, KeyEvent, RoutedEvent } from "keri";
import { NodeSqliteDatabase } from "../node/main.ts";
import { SqliteControllerStorage } from "../sqlite/main.ts";
import { Mailbox } from "./mailbox.ts";
import { createRouter } from "./mailbox-router.ts";

const URL_BASE = "http://mailbox.example";

function sign(payload: Uint8Array, options: { key: Uint8Array; index: number }): string {
  return encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(payload, options.key), options.index));
}

interface User {
  aid: string;
  key: KeyPair;
  kel: string;
  seal: { s: string; d: string };
}

function makeUser(): User {
  const key0 = generateKeyPair();
  const key1 = generateKeyPair();

  const icp = KeyEvent.incept({ signingKeys: [key0.publicKey], nextKeyDigests: [key1.publicKeyDigest] });
  icp.attachments.ControllerIdxSigs.push(sign(icp.raw, { key: key0.privateKey, index: 0 }));

  return {
    aid: icp.body.i,
    key: key0,
    kel: new TextDecoder().decode(icp.raw) + encodeText(icp.attachments.frames()),
    seal: { s: icp.body.s, d: icp.body.d },
  };
}

function makeRpy(user: User, overrides: { role?: string; eid: string; key?: KeyPair }): string {
  const rpy = RoutedEvent.reply({
    r: "/end/role/add",
    a: { cid: user.aid, role: overrides.role ?? "mailbox", eid: overrides.eid },
  });

  const key = overrides.key ?? user.key;
  rpy.attachments = {
    TransIdxSigGroups: [
      {
        prefix: user.aid,
        snu: user.seal.s,
        digest: user.seal.d,
        ControllerIdxSigs: [sign(rpy.raw, { key: key.privateKey, index: 0 })],
      },
    ],
  };

  return new TextDecoder().decode(rpy.raw) + encodeText(rpy.attachments.frames());
}

async function makeMailbox() {
  const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));
  const mailbox = await Mailbox.create({ storage, url: URL_BASE });
  return { mailbox, handler: createRouter(mailbox) };
}

function enrollRequest(kel: string, rpy: string): Request {
  const form = new FormData();
  form.set("kel", kel);
  form.set("rpy", rpy);
  return new Request(`${URL_BASE}/mailboxes`, { method: "POST", body: form });
}

describe(basename(import.meta.url), () => {
  test("should enroll a controller and serve its oobi", async () => {
    const { mailbox, handler } = await makeMailbox();
    const user = makeUser();

    const enrolled = await handler(enrollRequest(user.kel, makeRpy(user, { eid: mailbox.aid })));
    assert.strictEqual(enrolled.status, 200);

    const oobi = await handler(new Request(`${URL_BASE}/oobi/${user.aid}`));
    assert.strictEqual(oobi.status, 200);
    assert.strictEqual(oobi.headers.get("Keri-Aid"), user.aid);

    // KERIpy's emit order: the KEL, the mailbox's location, the end-role authorization.
    const messages = await Array.fromAsync(parse(await oobi.text()));
    assert.strictEqual(messages[0].body.t, "icp");
    assert.strictEqual(messages[0].body.i, user.aid);
    assert.strictEqual((messages[1].body as ReplyEventBody).r, "/loc/scheme");
    const endRole = messages[2] as Message<ReplyEventBody>;
    assert.strictEqual(endRole.body.r, "/end/role/add");
    assert.deepStrictEqual(endRole.body.a, { cid: user.aid, role: "mailbox", eid: mailbox.aid });
    // The controller's signature must survive the round trip.
    assert.strictEqual(endRole.attachments.TransIdxSigGroups.length, 1);
  });

  test("should reject an rpy signed by the wrong key", async () => {
    const { mailbox, handler } = await makeMailbox();
    const user = makeUser();

    const response = await handler(
      enrollRequest(user.kel, makeRpy(user, { eid: mailbox.aid, key: generateKeyPair() })),
    );
    assert.strictEqual(response.status, 400);
  });

  test("should reject an rpy naming a different mailbox", async () => {
    const { handler } = await makeMailbox();
    const user = makeUser();

    const response = await handler(enrollRequest(user.kel, makeRpy(user, { eid: "ENOTTHISMAILBOX" })));
    assert.strictEqual(response.status, 400);
  });

  test("should reject an rpy for a different role", async () => {
    const { mailbox, handler } = await makeMailbox();
    const user = makeUser();

    const response = await handler(enrollRequest(user.kel, makeRpy(user, { eid: mailbox.aid, role: "agent" })));
    assert.strictEqual(response.status, 400);
  });

  test("should reject a body that is not multipart form data", async () => {
    const { handler } = await makeMailbox();

    const response = await handler(new Request(`${URL_BASE}/mailboxes`, { method: "POST", body: "not a form" }));
    assert.strictEqual(response.status, 400);
  });

  test("should 404 an oobi for an unknown aid", async () => {
    const { handler } = await makeMailbox();

    const response = await handler(new Request(`${URL_BASE}/oobi/EUNKNOWNAIDAIDAIDAIDAIDAIDAIDAIDAIDAIDAIDAID`));
    assert.strictEqual(response.status, 404);
  });

  test("should keep serving its own oobi at the bare path and its own aid", async () => {
    const { mailbox, handler } = await makeMailbox();

    for (const path of ["/oobi", `/oobi/${mailbox.aid}`]) {
      const response = await handler(new Request(`${URL_BASE}${path}`));
      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.headers.get("Keri-Aid"), mailbox.aid);
      const messages = await Array.fromAsync(parse(await response.text()));
      assert.strictEqual(messages[0].body.i, mailbox.aid);
    }
  });
});
