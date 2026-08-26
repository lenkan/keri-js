import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeText, Indexer, Matter } from "../cesr/main.ts";
import { verifyReply } from "./exchange-verification.ts";
import { incept, interact, rotate } from "./key-event.ts";
import { KeyEventLog } from "./key-event-log.ts";
import { generateKeyPair, type KeyPair } from "./keys.ts";
import { reply } from "./routed-event.ts";
import { ed25519Signer, endorse, signEvent } from "./sign.ts";
import { verifyThreshold } from "./verify.ts";

describe(basename(import.meta.url), () => {
  const payload = new TextEncoder().encode("test message");

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

  describe("ed25519Signer", () => {
    test("should expose the public key matching the private key", () => {
      const { publicKey, privateKey } = generateKeyPair();
      assert.equal(ed25519Signer(privateKey).publicKey, publicKey);
    });

    test("should produce a signature that verifies against the key", () => {
      const { publicKey, privateKey } = generateKeyPair();
      const sig = ed25519Signer(privateKey).sign(payload);
      const indexedSig = encodeText(Indexer.convert(Matter.parse(sig), 0));
      const result = verifyThreshold(payload, { keys: [publicKey], sigs: [indexedSig], threshold: "1" });
      assert.deepEqual(result.ok, true);
    });

    test("should produce different signatures for different payloads", () => {
      const { privateKey } = generateKeyPair();
      const signer = ed25519Signer(privateKey);
      const other = new TextEncoder().encode("other message");
      assert.notStrictEqual(signer.sign(payload), signer.sign(other));
    });
  });

  describe("generateKeyPair", () => {
    test("should sign directly, without a separate signer", () => {
      const key = generateKeyPair();
      assert.equal(key.sign(payload), ed25519Signer(key.privateKey).sign(payload));
    });
  });

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

    test("should reject latest for a non-transferable identifier", () => {
      const key = generateKeyPair({ nonTransferable: true });
      const { log } = inceptLog([key], { nonTransferable: true });
      const rpy = reply({ r: "/loc/scheme", a: { eid: log.state.identifier } });

      assert.throws(() => endorse(rpy, { signers: [key], state: log.state, latest: true }), /can never rotate/);
    });
  });
});
