import assert from "node:assert";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Indexer, Matter, Message } from "../cesr/__main__.ts";
import { generateKeyPair } from "../core/keys.ts";
import { KeyEventLog, keri } from "../core/main.ts";
import { verifySignature } from "../core/verify.ts";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../storage/sqlite/storage-sqlite.ts";
import { Witness, WitnessError } from "./witness.ts";

function makeWitness(seed = "test-witness") {
  return new Witness({
    privateKey: generateKeyPair({ seed }).privateKey,
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
  });
}

interface InceptOptions {
  wits?: string[];
}

function createInceptEvent(options: InceptOptions = {}) {
  const { privateKey: controllerKey, publicKey: controllerPub } = generateKeyPair();
  const icp = keri.incept({ signingKeys: [controllerPub], nextKeys: [], wits: options.wits });
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

  const wig = receipt.attachments.NonTransReceiptCouples[0].sig;

  assert(verifySignature(msg.raw, Matter.parse(witness.aid), Matter.parse(wig).raw));
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

test("receipt() throws WitnessError when icp controller signature is invalid", () => {
  const witness = makeWitness();
  const { publicKey: controllerPub } = generateKeyPair();
  const icp = keri.incept({ signingKeys: [controllerPub], nextKeys: [] });

  const wrongKey = generateKeyPair().privateKey;
  const badSig = Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, wrongKey), 0).text();
  const msg = new Message(icp.body, { ControllerIdxSigs: [badSig] });

  assert.throws(() => witness.receipt(msg), WitnessError);
});

test("receipt() throws WitnessError when ixn controller signature is invalid", () => {
  const witness = makeWitness();
  const { privateKey: controllerKey, publicKey: controllerPub } = generateKeyPair();
  const icp = keri.incept({ signingKeys: [controllerPub], nextKeys: [] });
  const icpSig = Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, controllerKey), 0).text();
  witness.receipt(new Message(icp.body, { ControllerIdxSigs: [icpSig] }));

  const state = KeyEventLog.from(witness.getKeyEvents(icp.body.i)).state;
  const ixn = keri.interact(state);

  const wrongKey = generateKeyPair().privateKey;
  const badSig = Indexer.crypto.ed25519_sig(ed25519.sign(ixn.raw, wrongKey), 0).text();
  const msg = new Message(ixn.body, { ControllerIdxSigs: [badSig] });

  assert.throws(() => witness.receipt(msg), WitnessError);
});

test("handleMessage() is a no-op for non-rct events", () => {
  const witness = makeWitness();
  const icp = createInceptEvent();

  witness.handleMessage(icp);

  const stored = Array.from(witness.getKeyEvents(icp.body.i));
  assert.strictEqual(stored.length, 0);
});

test("handleMessage() is a no-op when this witness is not a backer", () => {
  const witness = makeWitness();
  const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
    seed: "other-witness",
    nonTransferable: true,
  });

  const icp = createInceptEvent({ wits: [otherPub] });
  witness.receipt(icp);

  const otherSig = new Matter({ code: Matter.Code.Ed25519_Sig, raw: ed25519.sign(icp.raw, otherKey) }).text();
  const rct = keri.receipt({ d: icp.body.d, i: icp.body.i, s: icp.body.s });
  const rctMsg = new Message(rct.body, {
    NonTransReceiptCouples: [{ prefix: otherPub, sig: otherSig }],
  });

  witness.handleMessage(rctMsg);

  const stored = Array.from(witness.getKeyEvents(icp.body.i));
  assert.strictEqual(stored[0]?.attachments.WitnessIdxSigs.length, 0);
});

test("handleMessage() merges NonTransReceiptCouples from another witness", () => {
  const witness = makeWitness();
  const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
    seed: "other-witness",
    nonTransferable: true,
  });

  const icp = createInceptEvent({ wits: [witness.aid, otherPub] });
  witness.receipt(icp);

  const before = Array.from(witness.getKeyEvents(icp.body.i));
  assert.strictEqual(before[0]?.attachments.WitnessIdxSigs.length, 1);

  const otherSig = new Matter({ code: Matter.Code.Ed25519_Sig, raw: ed25519.sign(icp.raw, otherKey) }).text();
  const rct = keri.receipt({ d: icp.body.d, i: icp.body.i, s: icp.body.s });
  const rctMsg = new Message(rct.body, {
    NonTransReceiptCouples: [{ prefix: otherPub, sig: otherSig }],
  });

  witness.handleMessage(rctMsg);

  const after = Array.from(witness.getKeyEvents(icp.body.i));
  assert.strictEqual(after[0]?.attachments.WitnessIdxSigs.length, 2);
});
