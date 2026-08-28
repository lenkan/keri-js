import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { incept, KeyEventLog, receipt, rotate, signEvent } from "../key-events/main.ts";
import { generateKeyPair, type KeyPair } from "../keys/main.ts";
import { endorse } from "./endorse.ts";
import { reply } from "./routed-event.ts";
import { verifyReply } from "./verification.ts";

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

  describe("endorse", () => {
    test("should attach a group naming the signer's last establishment event", () => {
      const key = generateKeyPair();
      const { log } = inceptLog([key]);
      const rpy = reply({ r: "/end/role/add", a: { cid: log.state.identifier } });

      endorse(rpy, { signers: [key], state: log.state });

      const [group] = rpy.attachments.TransIdxSigGroups;
      assert.equal(group.prefix, log.state.identifier);
      assert.equal(group.snu, log.state.lastEstablishment.s);
      assert.equal(group.digest, log.state.lastEstablishment.d);
      assert.deepEqual(verifyReply(rpy, log.state), { ok: true });
    });

    test("should attach a last-establishment group when latest is set", () => {
      const key = generateKeyPair();
      const { log } = inceptLog([key]);
      const rpy = reply({ r: "/end/role/add", a: { cid: log.state.identifier } });

      endorse(rpy, { signers: [key], state: log.state, latest: true });

      assert.equal(rpy.attachments.TransIdxSigGroups.length, 0);
      const [group] = rpy.attachments.TransLastIdxSigGroups;
      assert.equal(group.prefix, log.state.identifier);
      assert.deepEqual(verifyReply(rpy, log.state), { ok: true });
    });

    test("should attach a bare couple for a non-transferable identifier", () => {
      const key = generateKeyPair({ nonTransferable: true });
      const { log } = inceptLog([key], { nonTransferable: true });
      const rpy = reply({ r: "/loc/scheme", a: { eid: log.state.identifier } });

      endorse(rpy, { signers: [key], state: log.state });

      assert.equal(rpy.attachments.TransIdxSigGroups.length, 0);
      assert.deepEqual(rpy.attachments.NonTransReceiptCouples, [
        { prefix: log.state.identifier, sig: key.sign(rpy.raw) },
      ]);
    });

    // Two groups for one prefix would silently lose signatures: verifyReply
    // reads only the first group that matches.
    test("should fold a second endorsement into the group already present", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const { log } = inceptLog([key0, key1]);
      const rpy = reply({ r: "/end/role/add", a: { cid: log.state.identifier } });

      endorse(rpy, { signers: [key0], state: log.state });
      endorse(rpy, { signers: [key1], state: log.state });

      assert.equal(rpy.attachments.TransIdxSigGroups.length, 1);
      const [group] = rpy.attachments.TransIdxSigGroups;
      assert.equal(group.ControllerIdxSigs.length, 2);
      assert.deepEqual(verifyReply(rpy, log.state), { ok: true });
    });

    test("should not duplicate a signature already attached", () => {
      const key = generateKeyPair();
      const { log } = inceptLog([key]);
      const rpy = reply({ r: "/end/role/add", a: { cid: log.state.identifier } });

      endorse(rpy, { signers: [key], state: log.state });
      endorse(rpy, { signers: [key], state: log.state });

      assert.equal(rpy.attachments.TransIdxSigGroups[0].ControllerIdxSigs.length, 1);
    });

    test("should replace a group left by a superseded establishment event", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const icp = incept({ signingKeys: [key0.publicKey], nextKeyDigests: [key1.publicKeyDigest] });
      signEvent(icp, { signers: [key0] });
      const log = KeyEventLog.from([icp]);

      const rpy = reply({ r: "/end/role/add", a: { cid: log.state.identifier } });
      endorse(rpy, { signers: [key0], state: log.state });

      const rot = rotate(log.state, { signingKeys: [key1.publicKey], nextKeyDigests: [key0.publicKeyDigest] });
      signEvent(rot, { signers: [key1] });
      const rotated = log.append(rot);

      endorse(rpy, { signers: [key1], state: rotated.state });

      assert.equal(rpy.attachments.TransIdxSigGroups.length, 1);
      assert.equal(rpy.attachments.TransIdxSigGroups[0].digest, rotated.state.lastEstablishment.d);
      assert.deepEqual(verifyReply(rpy, rotated.state), { ok: true });
    });

    test("should replace a pinned group when re-endorsed with latest", () => {
      const key = generateKeyPair();
      const { log } = inceptLog([key]);
      const rpy = reply({ r: "/end/role/add", a: { cid: log.state.identifier } });

      endorse(rpy, { signers: [key], state: log.state });
      endorse(rpy, { signers: [key], state: log.state, latest: true });

      assert.equal(rpy.attachments.TransIdxSigGroups.length, 0);
      assert.equal(rpy.attachments.TransLastIdxSigGroups.length, 1);
      assert.deepEqual(verifyReply(rpy, log.state), { ok: true });
    });

    // The prefix decides the group, not the current keys: a transferable AID
    // stays transferable however it rotates.
    test("should sign as transferable after rotating to a non-transferable key", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair({ nonTransferable: true });
      const icp = incept({ signingKeys: [key0.publicKey], nextKeyDigests: [key1.publicKeyDigest] });
      signEvent(icp, { signers: [key0] });
      const log = KeyEventLog.from([icp]);

      const rot = rotate(log.state, { signingKeys: [key1.publicKey], nextKeyDigests: [key0.publicKeyDigest] });
      signEvent(rot, { signers: [key1] });
      const rotated = log.append(rot);

      const rpy = reply({ r: "/end/role/add", a: { cid: rotated.state.identifier } });
      endorse(rpy, { signers: [key1], state: rotated.state });

      assert.equal(rpy.attachments.NonTransReceiptCouples.length, 0);
      assert.equal(rpy.attachments.TransIdxSigGroups.length, 1);
      assert.deepEqual(verifyReply(rpy, rotated.state), { ok: true });
    });

    test("should reject a key event", () => {
      const key = generateKeyPair();
      const { event, log } = inceptLog([key]);

      assert.throws(() => endorse(event, { signers: [key], state: log.state }), /use signEvent\(\)/);
    });

    // A receipt is signed over the event it receipts, so endorsing it would sign the wrong bytes.
    test("should reject a receipt", () => {
      const key = generateKeyPair({ nonTransferable: true });
      const { event, log } = inceptLog([key], { nonTransferable: true });

      assert.throws(() => endorse(receipt(event), { signers: [key], state: log.state }), /use receipt\(\)/);
    });

    test("should reject latest for a non-transferable identifier", () => {
      const key = generateKeyPair({ nonTransferable: true });
      const { log } = inceptLog([key], { nonTransferable: true });
      const rpy = reply({ r: "/loc/scheme", a: { eid: log.state.identifier } });

      assert.throws(() => endorse(rpy, { signers: [key], state: log.state, latest: true }), /can never rotate/);
    });
  });
});
