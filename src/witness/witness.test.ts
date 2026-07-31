import assert from "node:assert";
import { basename } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, mock, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, Message } from "../cesr/main.ts";
import { generateKeyPair, KeyEventLog, keri, verifySignature } from "../core/main.ts";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../sqlite-storage/main.ts";
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
  const sig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, controllerKey), 0));
  return new Message(icp.body, { ControllerIdxSigs: [sig] });
}

describe(basename(import.meta.url), () => {
  test("should have a stable AID after construction", () => {
    const w1 = makeWitness();
    const w2 = makeWitness(); // same seed → same key → same AID
    assert.strictEqual(w1.aid, w2.aid);
    assert(w1.aid.length > 0);
  });

  describe("receipt()", () => {
    test("should endorse a valid event and return a receipt", () => {
      const witness = makeWitness();
      const msg = createInceptEvent({ wits: [witness.aid] });

      const receipt = witness.receipt(msg);

      assert.strictEqual(receipt.body.t, "rct");
      assert.strictEqual(receipt.body.i, msg.body.i);
      assert.strictEqual(receipt.attachments.NonTransReceiptCouples[0].prefix, witness.aid);

      const wig = receipt.attachments.NonTransReceiptCouples[0].sig;

      assert(verifySignature(msg.raw, Matter.parse(witness.aid), Matter.parse(wig).raw));
    });

    test("should throw WitnessError when witness is not a backer for the AID", () => {
      const witness = makeWitness();
      const msg = createInceptEvent(); // no witnesses listed

      assert.throws(() => witness.receipt(msg), WitnessError);
      assert.strictEqual(Array.from(witness.getKeyEvents(msg.body.i)).length, 0);
    });

    test("should throw WitnessError when no controller signatures are present", () => {
      const witness = makeWitness();
      const icp = createInceptEvent();
      const msg = new Message(icp.body, { ControllerIdxSigs: [] });

      assert.throws(() => witness.receipt(msg), WitnessError);
    });

    test("should store the event so getKeyEvents returns it", () => {
      const witness = makeWitness();
      const msg = createInceptEvent({ wits: [witness.aid] });

      witness.receipt(msg);

      const stored = Array.from(witness.getKeyEvents(msg.body.i));
      assert.strictEqual(stored.length, 1);
      assert.strictEqual(stored[0].body.t, "icp");
    });

    test("should throw WitnessError when icp controller signature is invalid", () => {
      const witness = makeWitness();
      const { publicKey: controllerPub } = generateKeyPair();
      const icp = keri.incept({ signingKeys: [controllerPub], nextKeys: [] });

      const wrongKey = generateKeyPair().privateKey;
      const badSig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, wrongKey), 0));
      const msg = new Message(icp.body, { ControllerIdxSigs: [badSig] });

      assert.throws(() => witness.receipt(msg), WitnessError);
    });

    test("should throw WitnessError when ixn controller signature is invalid", () => {
      const witness = makeWitness();
      const { privateKey: controllerKey, publicKey: controllerPub } = generateKeyPair();
      const icp = keri.incept({ signingKeys: [controllerPub], nextKeys: [], wits: [witness.aid] });
      const icpSig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, controllerKey), 0));

      witness.receipt(new Message(icp.body, { ControllerIdxSigs: [icpSig] }));

      const state = KeyEventLog.from(witness.getKeyEvents(icp.body.i)).state;
      const ixn = keri.interact(state);

      const wrongKey = generateKeyPair().privateKey;
      const badSig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(ixn.raw, wrongKey), 0));
      const msg = new Message(ixn.body, { ControllerIdxSigs: [badSig] });

      assert.throws(() => witness.receipt(msg), WitnessError);
    });
  });

  describe("getKeyEvents()", () => {
    test("should return empty for unknown AID", () => {
      const witness = makeWitness();
      const stored = Array.from(witness.getKeyEvents("unknown-aid"));
      assert.strictEqual(stored.length, 0);
    });
  });

  describe("handleMessage()", () => {
    test("should be a no-op for non-rct events", () => {
      const witness = makeWitness();
      const icp = createInceptEvent();

      witness.handleMessage(icp);

      const stored = Array.from(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(stored.length, 0);
    });

    test("should be a no-op for rct when no event is stored for that AID", () => {
      const witness = makeWitness();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        seed: "other-witness",
        nonTransferable: true,
      });

      const icp = createInceptEvent({ wits: [otherPub] });
      const otherSig = encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: ed25519.sign(icp.raw, otherKey) }));
      const rct = keri.receipt({ d: icp.body.d, i: icp.body.i, s: icp.body.s });
      const rctMsg = new Message(rct.body, {
        NonTransReceiptCouples: [{ prefix: otherPub, sig: otherSig }],
      });

      witness.handleMessage(rctMsg);

      const stored = Array.from(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(stored.length, 0);
    });

    test("should be a no-op for rct when witness is not in the AID's backer list", () => {
      const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));
      const { privateKey: ctlKey, publicKey: ctlPub } = generateKeyPair();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        seed: "other-witness",
        nonTransferable: true,
      });
      const icp = keri.incept({ signingKeys: [ctlPub], nextKeys: [], wits: [otherPub] });
      const icpSig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, ctlKey), 0));
      storage.saveMessage(new Message(icp.body, { ControllerIdxSigs: [icpSig] }));

      const witness = new Witness({
        privateKey: generateKeyPair({ seed: "test-witness" }).privateKey,
        storage,
      });

      const saveSpy = mock.method(storage, "saveMessage");

      const otherSig = encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: ed25519.sign(icp.raw, otherKey) }));
      const rct = keri.receipt({ d: icp.body.d, i: icp.body.i, s: icp.body.s });
      const rctMsg = new Message(rct.body, {
        NonTransReceiptCouples: [{ prefix: otherPub, sig: otherSig }],
      });

      witness.handleMessage(rctMsg);

      assert.strictEqual(saveSpy.mock.callCount(), 0);
    });

    test("should be a no-op for a malformed rct missing i/d", () => {
      const witness = makeWitness();
      // `i` omitted: without the presence guard this reaches getKeyEvents(undefined),
      // which node:sqlite rejects as an unsupported bind type.
      const rctMsg = new Message({ v: "KERI10JSON000000_", t: "rct", d: "", s: "0" } as never, {
        NonTransReceiptCouples: [],
      });

      assert.doesNotThrow(() => witness.handleMessage(rctMsg));
    });

    test("should merge NonTransReceiptCouples from another witness", () => {
      const witness = makeWitness();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        seed: "other-witness",
        nonTransferable: true,
      });

      const icp = createInceptEvent({ wits: [witness.aid, otherPub] });
      witness.receipt(icp);

      const before = Array.from(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(before[0]?.attachments.WitnessIdxSigs.length, 1);

      const otherSig = encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: ed25519.sign(icp.raw, otherKey) }));
      const rct = keri.receipt({ d: icp.body.d, i: icp.body.i, s: icp.body.s });
      const rctMsg = new Message(rct.body, {
        NonTransReceiptCouples: [{ prefix: otherPub, sig: otherSig }],
      });

      witness.handleMessage(rctMsg);

      const after = Array.from(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(after[0]?.attachments.WitnessIdxSigs.length, 2);
    });
  });
});
