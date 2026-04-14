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

// A simple inception event signed by a controller key
const controllerKey = ed25519.utils.randomSecretKey(createSeed("controller", "salt"));
const controllerPub = new Matter({ code: Matter.Code.Ed25519, raw: ed25519.getPublicKey(controllerKey) }).text();
const icp = keri.incept({ signingKeys: [controllerPub], nextKeys: [] });
const sig = Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, controllerKey), 0).text();

test("witness has a stable AID after construction", () => {
  const w1 = makeWitness();
  const w2 = makeWitness(); // same seed → same key → same AID
  assert.strictEqual(w1.aid, w2.aid);
  assert(w1.aid.length > 0);
});

test("receive() endorses a valid event and returns a receipt", () => {
  const witness = makeWitness();
  const msg = new Message(icp.body, { ControllerIdxSigs: [sig] });

  const receipt = witness.receive(msg);

  assert.strictEqual(receipt.body.t, "rct");
  assert.strictEqual(receipt.body.i, icp.body.i);
  assert.strictEqual(receipt.attachments.NonTransReceiptCouples[0].prefix, witness.aid);
});

test("receive() throws WitnessError when no controller signatures are present", () => {
  const witness = makeWitness();
  const msg = new Message(icp.body, { ControllerIdxSigs: [] });

  assert.throws(() => witness.receive(msg), WitnessError);
});
