import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Indexer, Matter } from "../cesr/main.ts";
import { incept } from "./key-event.ts";
import { generateKeyPair } from "./keys.ts";
import { applyReceipt, receipt } from "./receipt-event.ts";
import { signEvent } from "./sign.ts";
import { verifySignature } from "./verify.ts";

describe(basename(import.meta.url), () => {
  function witnessedEvent() {
    const controller = generateKeyPair();
    const next = generateKeyPair();
    const witnesses = [generateKeyPair({ nonTransferable: true }), generateKeyPair({ nonTransferable: true })];

    const event = incept({
      signingKeys: [controller.publicKey],
      nextKeyDigests: [next.publicKeyDigest],
      backers: witnesses.map((witness) => witness.publicKey),
    });
    signEvent(event, { signers: [controller] });

    return { event, witnesses, backers: witnesses.map((witness) => witness.publicKey) };
  }

  describe("receipt", () => {
    test("should copy d, i and s from the event it receipts", () => {
      const { event } = witnessedEvent();
      const rct = receipt(event);

      assert.equal(rct.body.t, "rct");
      assert.deepEqual(Object.keys(rct.body), ["v", "t", "d", "i", "s"]);
      assert.equal(rct.body.d, event.body.d);
      assert.equal(rct.body.i, event.body.i);
      assert.equal(rct.body.s, event.body.s);
    });

    test("should attach nothing without arguments", () => {
      const { event } = witnessedEvent();
      const rct = receipt(event);

      assert.equal(rct.attachments.WitnessIdxSigs.length, 0);
      assert.equal(rct.attachments.NonTransReceiptCouples.length, 0);
    });

    test("should throw when asked to sign with nothing", () => {
      const { event } = witnessedEvent();
      assert.throws(() => receipt(event, {}), { message: /Nothing to sign with/ });
    });

    // The whole point: a receipt endorses the event, so a signature over the receipt itself would
    // verify against nothing.
    test("should sign over the event, not over the receipt", () => {
      const { event, witnesses } = witnessedEvent();
      const rct = receipt(event, { signers: [witnesses[0]] });
      const { sig } = rct.attachments.NonTransReceiptCouples[0];

      assert.deepEqual(verifySignature(event.raw, witnesses[0].publicKey, sig), { ok: true });
      assert.equal(verifySignature(rct.raw, witnesses[0].publicKey, sig).ok, false);
    });

    test("should index a witness signature by its position in the backer set", () => {
      const { event, witnesses, backers } = witnessedEvent();
      const rct = receipt(event, { signers: [witnesses[1]], backers });

      assert.equal(rct.attachments.NonTransReceiptCouples.length, 0);
      assert.equal(Indexer.parse(rct.attachments.WitnessIdxSigs[0]).index, 1);
    });

    test("should write a bare couple for a signer outside the backer set", () => {
      const { event, backers } = witnessedEvent();
      const watcher = generateKeyPair({ nonTransferable: true });
      const rct = receipt(event, { signers: [watcher], backers });

      assert.equal(rct.attachments.WitnessIdxSigs.length, 0);
      assert.equal(rct.attachments.NonTransReceiptCouples[0].prefix, watcher.publicKey);
    });

    // Passing `backers` is the choice to receipt as a witness, which is how keripy splits
    // `Hab.witness` from `Hab.receipt`.
    test("should write a bare couple for a backer that does not name the backer set", () => {
      const { event, witnesses } = witnessedEvent();
      const rct = receipt(event, { signers: [witnesses[1]] });

      assert.equal(rct.attachments.WitnessIdxSigs.length, 0);
      assert.equal(rct.attachments.NonTransReceiptCouples[0].prefix, witnesses[1].publicKey);
    });

    test("should carry both groups when one signer is a backer and one is not", () => {
      const { event, witnesses, backers } = witnessedEvent();
      const watcher = generateKeyPair({ nonTransferable: true });
      const rct = receipt(event, { signers: [witnesses[0], watcher], backers });

      assert.equal(rct.attachments.WitnessIdxSigs.length, 1);
      assert.equal(rct.attachments.NonTransReceiptCouples.length, 1);
    });

    test("should throw for a transferable signer", () => {
      const { event, backers } = witnessedEvent();
      assert.throws(() => receipt(event, { signers: [generateKeyPair()], backers }), {
        message: /transferable.*endorse\(\)/,
      });
    });
  });

  describe("applyReceipt", () => {
    test("should carry an indexed signature across as it is", () => {
      const { event, witnesses, backers } = witnessedEvent();
      const rct = receipt(event, { signers: [witnesses[0]], backers });

      applyReceipt(event, rct, backers);

      assert.deepEqual(event.attachments.WitnessIdxSigs, rct.attachments.WitnessIdxSigs);
    });

    // What keripy's `Kevery.processReceipt` does: a couple whose prefix is in the witness list
    // becomes an indexed signature over the same bytes.
    test("should promote a couple naming a backer to an indexed signature", () => {
      const { event, witnesses, backers } = witnessedEvent();

      applyReceipt(event, receipt(event, { signers: [witnesses[1]] }), backers);

      const [sig] = event.attachments.WitnessIdxSigs;
      assert.equal(Indexer.parse(sig).index, 1);
      assert.deepEqual(Indexer.parse(sig).raw, Matter.parse(witnesses[1].sign(event.raw)).raw);
    });

    test("should drop a couple from outside the backer set", () => {
      const { event, backers } = witnessedEvent();
      const watcher = generateKeyPair({ nonTransferable: true });

      applyReceipt(event, receipt(event, { signers: [watcher] }), backers);

      assert.equal(event.attachments.WitnessIdxSigs.length, 0);
    });

    test("should accumulate receipts from every backer", () => {
      const { event, witnesses, backers } = witnessedEvent();

      applyReceipt(event, receipt(event, { signers: [witnesses[0]], backers }), backers);
      applyReceipt(event, receipt(event, { signers: [witnesses[1]] }), backers);

      assert.deepEqual(
        event.attachments.WitnessIdxSigs.map((sig) => Indexer.parse(sig).index),
        [0, 1],
      );
    });

    test("should not attach the same signature twice", () => {
      const { event, witnesses, backers } = witnessedEvent();
      const rct = receipt(event, { signers: [witnesses[0]], backers });

      applyReceipt(event, rct, backers);
      applyReceipt(event, rct, backers);

      assert.equal(event.attachments.WitnessIdxSigs.length, 1);
    });

    test("should throw when the receipt names a different event", () => {
      const { event, witnesses, backers } = witnessedEvent();
      const other = witnessedEvent();

      assert.throws(() => applyReceipt(event, receipt(other.event, { signers: [witnesses[0]], backers }), backers), {
        message: /Receipt is for /,
      });
    });

    test("should throw when a signature is indexed past the backer set", () => {
      const { event, witnesses, backers } = witnessedEvent();
      const rct = receipt(event, { signers: [witnesses[1]], backers });

      assert.throws(() => applyReceipt(event, rct, backers.slice(0, 1)), { message: /past the 1 backers/ });
    });
  });
});
