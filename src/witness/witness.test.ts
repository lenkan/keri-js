import assert from "node:assert";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Indexer, Matter, Message } from "../cesr/__main__.ts";
import { keri } from "../core/main.ts";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../storage/sqlite/storage-sqlite.ts";
import { createSeed } from "./seed.ts";
import { Witness, WitnessError } from "./witness.ts";

function makeWitness() {
  const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));
  return new Witness({
    privateKey: ed25519.utils.randomSecretKey(createSeed("test-witness", "salt")),
    storage,
  });
}

function createInceptEvent() {
  const controllerKey = ed25519.utils.randomSecretKey(createSeed("controller", "salt"));
  const controllerPub = new Matter({ code: Matter.Code.Ed25519, raw: ed25519.getPublicKey(controllerKey) }).text();
  const icp = keri.incept({ signingKeys: [controllerPub], nextKeys: [] });
  const sig = Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, controllerKey), 0).text();
  return new Message(icp.body, { ControllerIdxSigs: [sig] });
}

test("witness has a stable AID after construction", () => {
  const w1 = makeWitness();
  const w2 = makeWitness(); // same seed → same key → same AID
  assert.strictEqual(w1.aid, w2.aid);
  assert(w1.aid.length > 0);
});

test("receipt() endorses a valid event and returns a receipt", () => {
  const witness = makeWitness();
  const msg = createInceptEvent();

  const receipt = witness.receipt(msg);

  assert.strictEqual(receipt.body.t, "rct");
  assert.strictEqual(receipt.body.i, msg.body.i);
  assert.strictEqual(receipt.attachments.NonTransReceiptCouples[0].prefix, witness.aid);
});

test("receipt() throws WitnessError when no controller signatures are present", () => {
  const witness = makeWitness();
  const icp = createInceptEvent();
  const msg = new Message(icp.body, { ControllerIdxSigs: [] });

  assert.throws(() => witness.receipt(msg), WitnessError);
});

test("receipt() stores the event so getKeyEvents returns it", () => {
  const witness = makeWitness();
  const msg = createInceptEvent();

  witness.receipt(msg);

  const stored = Array.from(witness.getKeyEvents(msg.body.i));
  assert.strictEqual(stored.length, 1);
  assert.strictEqual(stored[0].body.t, "icp");
});

test("getKeyEvents() returns empty for unknown AID", () => {
  const witness = makeWitness();
  const stored = Array.from(witness.getKeyEvents("unknown-aid"));
  assert.strictEqual(stored.length, 0);
});
