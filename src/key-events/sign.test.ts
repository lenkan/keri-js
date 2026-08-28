import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Indexer } from "../cesr/main.ts";
import { generateKeyPair, type KeyPair, verifyThreshold } from "../keys/main.ts";
import { reply } from "../routed-events/main.ts";
import { incept, interact } from "./key-event.ts";
import { KeyEventLog } from "./log.ts";
import { signEvent } from "./sign.ts";

describe(basename(import.meta.url), () => {
  /** A signed inception plus the log it opens, so `state` is available. */
  function inceptLog(keys: KeyPair[], options?: { nonTransferable?: boolean }) {
    const next = generateKeyPair();
    const event = incept({
      signingKeys: keys.map((key) => key.publicKey),
      nextKeyDigests: options?.nonTransferable ? [] : [next.publicKeyDigest],
    });

    signEvent(event, { signers: keys });
    return { event, log: KeyEventLog.from([event]) };
  }

  describe("signEvent", () => {
    test("should attach one indexed signature per signer", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const { event } = inceptLog([key0, key1]);

      assert.equal(event.attachments.ControllerIdxSigs.length, 2);
      const result = verifyThreshold(event.raw, {
        keys: [key0.publicKey, key1.publicKey],
        sigs: event.attachments.ControllerIdxSigs,
        threshold: "2",
      });
      assert.deepEqual(result, { ok: true });
    });

    // Argument order carries no meaning: the index comes from where the key sits
    // in `k`, which is the position `verifyThreshold` resolves it back from.
    test("should index by key position, not by argument order", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const next = generateKeyPair();

      const event = incept({
        signingKeys: [key0.publicKey, key1.publicKey],
        nextKeyDigests: [next.publicKeyDigest],
      });

      signEvent(event, { signers: [key1, key0] });

      const result = verifyThreshold(event.raw, {
        keys: [key0.publicKey, key1.publicKey],
        sigs: event.attachments.ControllerIdxSigs,
        threshold: "2",
      });
      assert.deepEqual(result, { ok: true });
    });

    test("should index a subset of the signing keys correctly", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const next = generateKeyPair();

      const event = incept({
        signingKeys: [key0.publicKey, key1.publicKey],
        nextKeyDigests: [next.publicKeyDigest],
      });

      signEvent(event, { signers: [key1] });

      assert.equal(Indexer.parse(event.attachments.ControllerIdxSigs[0]).index, 1);
      const result = verifyThreshold(event.raw, {
        keys: [key0.publicKey, key1.publicKey],
        sigs: event.attachments.ControllerIdxSigs,
        threshold: "1",
      });
      assert.deepEqual(result, { ok: true });
    });

    test("should accept signatures produced elsewhere", () => {
      const key = generateKeyPair();
      const next = generateKeyPair();
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });

      signEvent(event, { signatures: [{ publicKey: key.publicKey, signature: key.sign(event.raw) }] });

      const result = verifyThreshold(event.raw, {
        keys: [key.publicKey],
        sigs: event.attachments.ControllerIdxSigs,
        threshold: "1",
      });
      assert.deepEqual(result, { ok: true });
    });

    test("should take the signing keys from the state for an interaction", () => {
      const key = generateKeyPair();
      const { log } = inceptLog([key]);
      const ixn = interact(log.state);

      signEvent(ixn, { signers: [key], state: log.state });

      const result = verifyThreshold(ixn.raw, {
        keys: log.state.signingKeys,
        sigs: ixn.attachments.ControllerIdxSigs,
        threshold: "1",
      });
      assert.deepEqual(result, { ok: true });
    });

    test("should not duplicate a signature already attached", () => {
      const key = generateKeyPair();
      const next = generateKeyPair();
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });

      signEvent(event, { signers: [key] });
      signEvent(event, { signers: [key] });

      assert.equal(event.attachments.ControllerIdxSigs.length, 1);
    });

    test("should return the same message so calls can be chained", () => {
      const key = generateKeyPair();
      const next = generateKeyPair();
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });

      assert.equal(signEvent(event, { signers: [key] }), event);
    });

    test("should reject a key that is not one of the signing keys", () => {
      const key = generateKeyPair();
      const stranger = generateKeyPair();
      const next = generateKeyPair();
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });

      assert.throws(() => signEvent(event, { signers: [stranger] }), /is not one of the signing keys/);
    });

    test("should reject an interaction without the signer's key state", () => {
      const key = generateKeyPair();
      const { log } = inceptLog([key]);
      const ixn = interact(log.state);

      assert.throws(() => signEvent(ixn, { signers: [key] }), /needs the signer's key state/);
    });

    test("should reject a state belonging to another identifier", () => {
      const key = generateKeyPair();
      const { log } = inceptLog([key]);
      const other = inceptLog([generateKeyPair()]);

      assert.throws(() => signEvent(other.event, { signers: [key], state: log.state }), /not/);
    });

    test("should reject a routed message", () => {
      const key = generateKeyPair();
      const rpy = reply({ r: "/end/role/add", a: {} });

      assert.throws(() => signEvent(rpy, { signers: [key] }), /use endorse\(\)/);
    });

    test("should reject signing with nothing", () => {
      const key = generateKeyPair();
      const next = generateKeyPair();
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });

      assert.throws(() => signEvent(event, {}), /Nothing to sign with/);
    });
  });
});
