import assert from "node:assert";
import { basename } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, mock, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { encodeText, Indexer, Matter, Message } from "cesr";
import { generateKeyPair, KeyEvent, KeyEventLog, verifySignature } from "keri";
import { NodeSqliteDatabase, SqliteControllerStorage } from "../node/main.ts";
import { Witness, WitnessError } from "./witness.ts";

function makeWitness(insecureSeed = "test-witness") {
  return Witness.create({
    privateKey: generateKeyPair({ insecureSeed }).privateKey,
    storage: new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:"))),
  });
}

interface InceptOptions {
  wits?: string[];
}

function createInceptEvent(options: InceptOptions = {}) {
  const { privateKey: controllerKey, publicKey: controllerPub } = generateKeyPair();
  const icp = KeyEvent.incept({ signingKeys: [controllerPub], nextKeyDigests: [], backers: options.wits });
  const sig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, controllerKey), 0));
  return new Message(icp.body, { ControllerIdxSigs: [sig] });
}

describe(basename(import.meta.url), () => {
  test("should have a stable AID after construction", async () => {
    const w1 = await makeWitness();
    const w2 = await makeWitness(); // same seed → same key → same AID
    assert.strictEqual(w1.aid, w2.aid);
    assert(w1.aid.length > 0);
  });

  describe("receipt()", () => {
    test("should endorse a valid event and return a receipt", async () => {
      const witness = await makeWitness();
      const msg = createInceptEvent({ wits: [witness.aid] });

      const receipt = await witness.receipt(msg);

      assert.strictEqual(receipt.body.t, "rct");
      assert.strictEqual(receipt.body.i, msg.body.i);
      assert.strictEqual(receipt.attachments.NonTransReceiptCouples[0].prefix, witness.aid);

      const wig = receipt.attachments.NonTransReceiptCouples[0].sig;

      assert(verifySignature(msg.raw, witness.aid, wig).ok);
    });

    test("should throw WitnessError when witness is not a backer for the AID", async () => {
      const witness = await makeWitness();
      const msg = createInceptEvent(); // no witnesses listed

      await assert.rejects(() => witness.receipt(msg), WitnessError);
      assert.strictEqual(Array.from(witness.getKeyEvents(msg.body.i)).length, 0);
    });

    test("should throw WitnessError when no controller signatures are present", async () => {
      const witness = await makeWitness();
      const icp = createInceptEvent();
      const msg = new Message(icp.body, { ControllerIdxSigs: [] });

      await assert.rejects(() => witness.receipt(msg), WitnessError);
    });

    test("should store the event so getKeyEvents returns it", async () => {
      const witness = await makeWitness();
      const msg = createInceptEvent({ wits: [witness.aid] });

      await witness.receipt(msg);

      const stored = Array.from(witness.getKeyEvents(msg.body.i));
      assert.strictEqual(stored.length, 1);
      assert.strictEqual(stored[0].body.t, "icp");
    });

    test("should throw WitnessError when icp controller signature is invalid", async () => {
      const witness = await makeWitness();
      const { publicKey: controllerPub } = generateKeyPair();
      const icp = KeyEvent.incept({ signingKeys: [controllerPub], nextKeyDigests: [] });

      const wrongKey = generateKeyPair().privateKey;
      const badSig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, wrongKey), 0));
      const msg = new Message(icp.body, { ControllerIdxSigs: [badSig] });

      await assert.rejects(() => witness.receipt(msg), WitnessError);
    });

    test("should throw WitnessError when ixn controller signature is invalid", async () => {
      const witness = await makeWitness();
      const { privateKey: controllerKey, publicKey: controllerPub } = generateKeyPair();
      const icp = KeyEvent.incept({ signingKeys: [controllerPub], nextKeyDigests: [], backers: [witness.aid] });
      const icpSig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, controllerKey), 0));

      await witness.receipt(new Message(icp.body, { ControllerIdxSigs: [icpSig] }));

      const state = KeyEventLog.from(witness.getKeyEvents(icp.body.i)).state;
      const ixn = KeyEvent.interact(state);

      const wrongKey = generateKeyPair().privateKey;
      const badSig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(ixn.raw, wrongKey), 0));
      const msg = new Message(ixn.body, { ControllerIdxSigs: [badSig] });

      await assert.rejects(() => witness.receipt(msg), WitnessError);
    });
  });

  describe("getKeyEvents()", () => {
    test("should return empty for unknown AID", async () => {
      const witness = await makeWitness();
      const stored = Array.from(witness.getKeyEvents("unknown-aid"));
      assert.strictEqual(stored.length, 0);
    });
  });

  describe("handleMessage()", () => {
    test("should be a no-op for non-rct events", async () => {
      const witness = await makeWitness();
      const icp = createInceptEvent();

      witness.handleMessage(icp);

      const stored = Array.from(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(stored.length, 0);
    });

    test("should be a no-op for rct when no event is stored for that AID", async () => {
      const witness = await makeWitness();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        insecureSeed: "other-witness",
        nonTransferable: true,
      });

      const icp = createInceptEvent({ wits: [otherPub] });
      const otherSig = encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: ed25519.sign(icp.raw, otherKey) }));
      const rct = KeyEvent.receipt(icp);
      const rctMsg = new Message(rct.body, {
        NonTransReceiptCouples: [{ prefix: otherPub, sig: otherSig }],
      });

      witness.handleMessage(rctMsg);

      const stored = Array.from(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(stored.length, 0);
    });

    test("should be a no-op for rct when witness is not in the AID's backer list", async () => {
      const storage = new SqliteControllerStorage(new NodeSqliteDatabase(new DatabaseSync(":memory:")));
      const { privateKey: ctlKey, publicKey: ctlPub } = generateKeyPair();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        insecureSeed: "other-witness",
        nonTransferable: true,
      });
      const icp = KeyEvent.incept({ signingKeys: [ctlPub], nextKeyDigests: [], backers: [otherPub] });
      const icpSig = encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(icp.raw, ctlKey), 0));
      storage.saveMessage(new Message(icp.body, { ControllerIdxSigs: [icpSig] }));

      const witness = await Witness.create({
        privateKey: generateKeyPair({ insecureSeed: "test-witness" }).privateKey,
        storage,
      });

      const saveSpy = mock.method(storage, "saveMessage");

      const otherSig = encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: ed25519.sign(icp.raw, otherKey) }));
      const rct = KeyEvent.receipt(icp);
      const rctMsg = new Message(rct.body, {
        NonTransReceiptCouples: [{ prefix: otherPub, sig: otherSig }],
      });

      witness.handleMessage(rctMsg);

      assert.strictEqual(saveSpy.mock.callCount(), 0);
    });

    test("should merge NonTransReceiptCouples from another witness", async () => {
      const witness = await makeWitness();
      const { privateKey: otherKey, publicKey: otherPub } = generateKeyPair({
        insecureSeed: "other-witness",
        nonTransferable: true,
      });

      const icp = createInceptEvent({ wits: [witness.aid, otherPub] });
      await witness.receipt(icp);

      const before = Array.from(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(before[0]?.attachments.WitnessIdxSigs.length, 1);

      const otherSig = encodeText(new Matter({ code: Matter.Code.Ed25519_Sig, raw: ed25519.sign(icp.raw, otherKey) }));
      const rct = KeyEvent.receipt(icp);
      const rctMsg = new Message(rct.body, {
        NonTransReceiptCouples: [{ prefix: otherPub, sig: otherSig }],
      });

      witness.handleMessage(rctMsg);

      const after = Array.from(witness.getKeyEvents(icp.body.i));
      assert.strictEqual(after[0]?.attachments.WitnessIdxSigs.length, 2);
    });
  });
});
