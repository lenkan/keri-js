import assert from "node:assert/strict";
import { createReadStream } from "node:fs";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Message } from "cesr";
import { delegatedIncept, delegatedRotate, incept, interact, rotate } from "./key-event.ts";
import { KeyEventLog } from "./key-event-log.ts";
import { generateKeyPair, type KeyPair } from "./keys.ts";
import { signWith as sign } from "./signing.test.ts";

function inceptLog(key: KeyPair, nextKey: KeyPair): KeyEventLog {
  const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [nextKey.publicKeyDigest] });
  const sigs = sign(event, [key]);
  return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
}

describe(basename(import.meta.url), () => {
  test("should create log at sequence 0 when appending icp", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const log = inceptLog(key0, key1);
    assert.equal(log.state.lastEvent.s, "0");
  });

  test("should throw on missing signatures when appending icp", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const event = incept({ signingKeys: [key0.publicKey], nextKeyDigests: [key1.publicKeyDigest] });
    assert.throws(() => KeyEventLog.empty().append(new Message(event.body)), {
      message: "Threshold not met: 0 weight provided, but 1 required",
    });
  });

  test("should advance sequence when appending ixn", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const log = inceptLog(key0, key1);
    const event = interact(log.state, { data: { test: "data" } });
    const sigs = sign(event, [key0]);
    const log2 = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
    assert.equal(log2.state.lastEvent.s, "1");
  });

  test("should advance sequence and update keys when appending rot", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const log = inceptLog(key0, key1);
    const event = rotate(log.state, { signingKeys: [key1.publicKey], nextKeyDigests: [key0.publicKeyDigest] });
    // Signed by the newly exposed key, whose digest the icp committed to.
    const sigs = sign(event, [key1]);
    const log2 = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
    assert.equal(log2.state.lastEvent.s, "1");
    assert.deepEqual(log2.state.signingKeys, [key1.publicKey]);
  });

  test("should reject a rot signed by the superseded key", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const log = inceptLog(key0, key1);
    const event = rotate(log.state, { signingKeys: [key1.publicKey], nextKeyDigests: [key0.publicKeyDigest] });
    const sigs = sign(event, [key0]);
    assert.throws(() => log.append(new Message(event.body, { ControllerIdxSigs: sigs })), {
      message: /Invalid signature/,
    });
  });

  test("should reject a rot exposing a key the prior event never committed to", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();
    const intruder = generateKeyPair();

    const log = inceptLog(key0, key1);
    const event = rotate(log.state, { signingKeys: [intruder.publicKey], nextKeyDigests: [key0.publicKeyDigest] });
    const sigs = sign(event, [intruder]);
    assert.throws(() => log.append(new Message(event.body, { ControllerIdxSigs: sigs })), {
      message: /was not committed by the prior establishment event/,
    });
  });

  test("should parse alice.cesr into a valid key event log", async () => {
    const stream = createReadStream(new URL("../../../../fixtures/alice.cesr", import.meta.url));
    const log = await KeyEventLog.parse(stream);

    assert.equal(log.events.length, 2);
    assert.equal(log.state.identifier, "EPoVUviPdemgkjAhPnp7Q0bvMutVyd9BdIOLlZR8UE1y");
    assert.equal(log.state.lastEvent.s, "1");
    assert.equal(log.state.lastEvent.d, "EIybyHwRGcth--_AiIO6SNN2-VSYZqezeEphEChn3XIM");
  });

  // delegated.cesr is a witness OOBI response captured from KERIpy 1.3.3 for
  // a delegated AID. The stream contains the delegator's KEL chain followed
  // by the delegate's dip. KeyEventLog.parse splits the multi-AID stream,
  // builds the delegator log first, and verifies the dip's SealSourceCouple
  // against the delegator's anchoring ixn.
  test("should parse delegated.cesr and verify the delegator anchor", async () => {
    const delegatorAid = "EO662-g789YVjlSwIqhFdh9sWFWL5XHRNtTTM-7XWVeL";
    const delegateAid = "EOTtln9o6PLRuYh8Oq1t8ht6qWI4pwncznbihhPWzFgv";
    const stream = createReadStream(new URL("../../../../fixtures/delegated.cesr", import.meta.url));

    const log = await KeyEventLog.parse(stream, { allowPartiallyWitnessed: true });

    assert.equal(log.state.identifier, delegateAid);
    assert.equal(log.state.delegator, delegatorAid);
    assert.equal(log.state.lastEvent.s, "0");
    assert.equal(log.events[0].body.t, "dip");

    assert.ok(log.delegator, "Expected a nested delegator KEL");
    assert.equal(log.delegator.state.identifier, delegatorAid);

    // The delegator must contain at least one event whose `a` field carries a
    // key-event seal matching the dip (i, s, d). Without this assertion the
    // test would still pass if anchor verification silently no-op'd.
    const dip = log.events[0];
    const anchor = log.delegator.events.find((e) => {
      const seals = (e.body as { a?: { i?: string; s?: string; d?: string }[] }).a ?? [];
      return seals.some((seal) => seal.i === dip.body.i && seal.s === dip.body.s && seal.d === dip.body.d);
    });
    assert.ok(anchor, "Expected delegator KEL to contain an event whose `a` anchors the dip");
    assert.equal(anchor.body.t, "ixn");
  });

  describe("allowPartiallySigned", () => {
    test("should allow appending icp with no controller sigs", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const event = incept({ signingKeys: [key0.publicKey], nextKeyDigests: [key1.publicKeyDigest] });
      const log = KeyEventLog.empty().append(new Message(event.body), { allowPartiallySigned: true });
      assert.equal(log.state.lastEvent.s, "0");
    });

    test("should still throw on cryptographically invalid controller sig", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const wrongKey = generateKeyPair();
      const event = incept({ signingKeys: [key0.publicKey], nextKeyDigests: [key1.publicKeyDigest] });
      const wrongSigs = sign(event, [wrongKey]);
      assert.throws(
        () =>
          KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: wrongSigs }), {
            allowPartiallySigned: true,
          }),
        { message: "Invalid signature for key at index 0" },
      );
    });
  });

  describe("allowPartiallyWitnessed", () => {
    test("should allow appending witnessed icp with no witness sigs", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const witnessKey = generateKeyPair();
      const event = incept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        backers: [witnessKey.publicKey],
      });
      const controllerSigs = sign(event, [key0]);
      const log = KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: controllerSigs }), {
        allowPartiallyWitnessed: true,
      });
      assert.equal(log.state.lastEvent.s, "0");
    });

    test("should throw on missing witness sigs by default", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const witnessKey = generateKeyPair();
      const event = incept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        backers: [witnessKey.publicKey],
      });
      const controllerSigs = sign(event, [key0]);
      assert.throws(() => KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: controllerSigs })), {
        message: /Threshold not met/,
      });
    });

    test("should still throw on cryptographically invalid witness sig", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const witnessKey = generateKeyPair();
      const wrongWitnessKey = generateKeyPair();
      const event = incept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        backers: [witnessKey.publicKey],
      });
      const controllerSigs = sign(event, [key0]);
      const wrongWitnessSigs = sign(event, [wrongWitnessKey]);
      assert.throws(
        () =>
          KeyEventLog.empty().append(
            new Message(event.body, { ControllerIdxSigs: controllerSigs, WitnessIdxSigs: wrongWitnessSigs }),
            { allowPartiallyWitnessed: true },
          ),
        { message: "Invalid signature for key at index 0" },
      );
    });
  });

  describe("delegated", () => {
    const delegator = "EAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    function dipLog(key: KeyPair, nextKey: KeyPair): KeyEventLog {
      const event = delegatedIncept({
        signingKeys: [key.publicKey],
        nextKeyDigests: [nextKey.publicKeyDigest],
        delegator,
      });
      const sigs = sign(event, [key]);
      return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
    }

    test("should append dip without SealSourceCouple and record delegator on state", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const log = dipLog(key0, key1);
      assert.equal(log.state.lastEvent.s, "0");
      assert.equal(log.state.delegator, delegator);
    });

    test("should accept dip with SealSourceCouple attachment", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const event = delegatedIncept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        delegator,
      });
      const sigs = sign(event, [key0]);
      const couple = { snu: "0", digest: "EAbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" };
      const message = new Message(event.body, {
        ControllerIdxSigs: sigs,
        SealSourceCouples: [couple],
      });
      const log = KeyEventLog.empty().append(message);
      assert.equal(log.state.delegator, delegator);
      assert.deepEqual(log.events[0].attachments.SealSourceCouples, [couple]);
    });

    test("should append drt and preserve delegator", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const key2 = generateKeyPair();
      const log = dipLog(key0, key1);
      const event = delegatedRotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [key2.publicKeyDigest],
      });
      const sigs = sign(event, [key1]);
      const log2 = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
      assert.equal(log2.state.lastEvent.s, "1");
      assert.equal(log2.state.delegator, delegator);
      assert.deepEqual(log2.state.signingKeys, [key1.publicKey]);
    });

    test("should preserve delegator across ixn", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const log = dipLog(key0, key1);
      const event = interact(log.state);
      const sigs = sign(event, [key0]);
      const log2 = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
      assert.equal(log2.state.delegator, delegator);
    });

    test("should reject drt missing controller signature", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const key2 = generateKeyPair();
      const log = dipLog(key0, key1);
      const event = delegatedRotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [key2.publicKeyDigest],
      });
      assert.throws(() => log.append(new Message(event.body)), {
        message: /Threshold not met/,
      });
    });
  });

  describe("delegator anchor verification", () => {
    /** Builds a non-delegated KEL acting as the delegator. */
    function makeDelegator(key: KeyPair, nextKey: KeyPair): KeyEventLog {
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [nextKey.publicKeyDigest] });
      const sigs = sign(event, [key]);
      return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
    }

    /** Anchors a dip in the delegator's KEL via an ixn whose `a` carries a key-event seal. */
    function anchorDip(
      delegator: KeyEventLog,
      delegatorKey: KeyPair,
      dipBody: { i: string; s: string; d: string },
    ): KeyEventLog {
      const ixn = interact(delegator.state, { data: { i: dipBody.i, s: dipBody.s, d: dipBody.d } });
      const sigs = sign(ixn, [delegatorKey]);
      return delegator.append(new Message(ixn.body, { ControllerIdxSigs: sigs }));
    }

    test("should accept dip when delegator KEL contains a matching anchor seal", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();

      let delegator = makeDelegator(delegatorKey, delegatorNext);

      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeyDigests: [delegateNext.publicKeyDigest],
        delegator: delegator.state.identifier,
      });

      delegator = anchorDip(delegator, delegatorKey, dip.body);

      const dipSigs = sign(dip, [delegateKey]);
      const log = KeyEventLog.empty().append(new Message(dip.body, { ControllerIdxSigs: dipSigs }), { delegator });

      assert.equal(log.state.delegator, delegator.state.identifier);
      assert.ok(log.delegator, "Expected the appended dip to retain the delegator KEL");
      assert.equal(log.delegator.state.identifier, delegator.state.identifier);
    });

    test("should throw when delegator KEL has no event anchoring the dip", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();

      const delegator = makeDelegator(delegatorKey, delegatorNext);

      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeyDigests: [delegateNext.publicKeyDigest],
        delegator: delegator.state.identifier,
      });
      const dipSigs = sign(dip, [delegateKey]);

      assert.throws(
        () => KeyEventLog.empty().append(new Message(dip.body, { ControllerIdxSigs: dipSigs }), { delegator }),
        { message: /No anchoring event found in delegator KEL/ },
      );
    });

    test("should throw when SealSourceCouple points to an event missing the seal", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();

      // The delegator has an icp but no anchoring ixn — yet the dip carries a
      // SealSourceCouple pointing at the icp. Verification must reject.
      const delegator = makeDelegator(delegatorKey, delegatorNext);

      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeyDigests: [delegateNext.publicKeyDigest],
        delegator: delegator.state.identifier,
      });
      const dipSigs = sign(dip, [delegateKey]);
      const message = new Message(dip.body, {
        ControllerIdxSigs: dipSigs,
        SealSourceCouples: [{ snu: delegator.state.lastEvent.s, digest: delegator.state.lastEvent.d }],
      });

      assert.throws(() => KeyEventLog.empty().append(message, { delegator }), {
        message: /does not anchor dip/,
      });
    });

    test("should throw when dip.di does not match delegator KEL identifier", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();

      const delegator = makeDelegator(delegatorKey, delegatorNext);
      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeyDigests: [delegateNext.publicKeyDigest],
        delegator: "EAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      });
      const dipSigs = sign(dip, [delegateKey]);

      assert.throws(
        () => KeyEventLog.empty().append(new Message(dip.body, { ControllerIdxSigs: dipSigs }), { delegator }),
        { message: /Delegation mismatch/ },
      );
    });

    test("should retain delegator across subsequent ixn/drt appends and re-verify drt anchor", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();
      const delegateNext2 = generateKeyPair();

      let delegator = makeDelegator(delegatorKey, delegatorNext);

      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeyDigests: [delegateNext.publicKeyDigest],
        delegator: delegator.state.identifier,
      });
      delegator = anchorDip(delegator, delegatorKey, dip.body);

      const dipSigs = sign(dip, [delegateKey]);
      let dipLog = KeyEventLog.empty().append(new Message(dip.body, { ControllerIdxSigs: dipSigs }), { delegator });

      const ixn = interact(dipLog.state);
      const ixnSigs = sign(ixn, [delegateKey]);
      dipLog = dipLog.append(new Message(ixn.body, { ControllerIdxSigs: ixnSigs }));

      assert.ok(dipLog.delegator, "Delegator should remain attached after ixn");
      assert.equal(dipLog.delegator.state.identifier, delegator.state.identifier);

      // Build a drt and anchor it via a fresh delegator ixn — the drt's
      // append must re-run verifyDelegationAnchor against the now-extended
      // delegator KEL and succeed.
      const drt = delegatedRotate(dipLog.state, {
        signingKeys: [delegateNext.publicKey],
        nextKeyDigests: [delegateNext2.publicKeyDigest],
      });
      const drtAnchored = anchorDip(delegator, delegatorKey, drt.body);
      const drtSigs = sign(drt, [delegateNext]);
      const drtLog = dipLog.append(new Message(drt.body, { ControllerIdxSigs: drtSigs }), { delegator: drtAnchored });

      assert.equal(drtLog.state.lastEvent.s, "2");
      assert.ok(drtLog.delegator);
      // Delegator KEL now has icp (s=0), first anchor ixn (s=1), drt anchor ixn (s=2).
      assert.equal(drtLog.delegator.state.lastEvent.s, "2");
    });

    test("should throw when drt is not anchored in the delegator KEL", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();
      const delegateNext2 = generateKeyPair();

      let delegator = makeDelegator(delegatorKey, delegatorNext);

      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeyDigests: [delegateNext.publicKeyDigest],
        delegator: delegator.state.identifier,
      });
      delegator = anchorDip(delegator, delegatorKey, dip.body);

      const dipSigs = sign(dip, [delegateKey]);
      const dipLog = KeyEventLog.empty().append(new Message(dip.body, { ControllerIdxSigs: dipSigs }), { delegator });

      // Build a drt but DON'T anchor it in the delegator KEL.
      const drt = delegatedRotate(dipLog.state, {
        signingKeys: [delegateNext.publicKey],
        nextKeyDigests: [delegateNext2.publicKeyDigest],
      });
      const drtSigs = sign(drt, [delegateNext]);

      assert.throws(() => dipLog.append(new Message(drt.body, { ControllerIdxSigs: drtSigs }), { delegator }), {
        message: /No anchoring event found in delegator KEL/,
      });
    });

    test("should accept dip when SealSourceTriple with matching prefix points at the anchoring event", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();

      let delegator = makeDelegator(delegatorKey, delegatorNext);
      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeyDigests: [delegateNext.publicKeyDigest],
        delegator: delegator.state.identifier,
      });
      delegator = anchorDip(delegator, delegatorKey, dip.body);

      const anchorIxn = delegator.events[1];
      const dipSigs = sign(dip, [delegateKey]);
      const message = new Message(dip.body, {
        ControllerIdxSigs: dipSigs,
        SealSourceTriples: [{ prefix: delegator.state.identifier, snu: anchorIxn.body.s, digest: anchorIxn.body.d }],
      });

      const log = KeyEventLog.empty().append(message, { delegator });
      assert.equal(log.state.delegator, delegator.state.identifier);
    });

    test("should ignore SealSourceTriple whose prefix does not match the delegator AID", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();

      let delegator = makeDelegator(delegatorKey, delegatorNext);
      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeyDigests: [delegateNext.publicKeyDigest],
        delegator: delegator.state.identifier,
      });
      delegator = anchorDip(delegator, delegatorKey, dip.body);

      // Triple's prefix references a different AID. The filter drops it,
      // so verification falls back to scanning the delegator KEL — which
      // does contain the matching anchor. Append must succeed.
      const anchorIxn = delegator.events[1];
      const dipSigs = sign(dip, [delegateKey]);
      const message = new Message(dip.body, {
        ControllerIdxSigs: dipSigs,
        SealSourceTriples: [
          { prefix: "EAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", snu: anchorIxn.body.s, digest: anchorIxn.body.d },
        ],
      });

      const log = KeyEventLog.empty().append(message, { delegator });
      assert.equal(log.state.delegator, delegator.state.identifier);
    });
  });

  describe("KeyEventLog.fromMessages", () => {
    test("should return empty log for empty input", () => {
      const log = KeyEventLog.fromMessages([]);
      assert.equal(log.events.length, 0);
    });

    test("should throw 'cycle' when two delegated AIDs reference each other", () => {
      const keyA = generateKeyPair();
      const nextA = generateKeyPair();
      const keyB = generateKeyPair();
      const nextB = generateKeyPair();

      // Two dip events whose `di` fields cross-reference: no leaf.
      const dipA = delegatedIncept({
        signingKeys: [keyA.publicKey],
        nextKeyDigests: [nextA.publicKeyDigest],
        delegator: "EBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      });
      const dipB = delegatedIncept({
        signingKeys: [keyB.publicKey],
        nextKeyDigests: [nextB.publicKeyDigest],
        delegator: "EAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      });
      // Override di to point at each other's i (di must reference real AIDs).
      const bodyA = { ...dipA.body, di: dipB.body.i };
      const bodyB = { ...dipB.body, di: dipA.body.i };

      assert.throws(
        () =>
          KeyEventLog.fromMessages([
            new Message(bodyA, { ControllerIdxSigs: sign(dipA, [keyA]) }),
            new Message(bodyB, { ControllerIdxSigs: sign(dipB, [keyB]) }),
          ]),
        { message: /no leaf AID/ },
      );
    });

    test("should throw 'ambiguous' for two unrelated non-delegated AIDs", () => {
      const k0 = generateKeyPair();
      const n0 = generateKeyPair();
      const k1 = generateKeyPair();
      const n1 = generateKeyPair();

      const a = incept({ signingKeys: [k0.publicKey], nextKeyDigests: [n0.publicKeyDigest] });
      const b = incept({ signingKeys: [k1.publicKey], nextKeyDigests: [n1.publicKeyDigest] });

      assert.throws(
        () =>
          KeyEventLog.fromMessages([
            new Message(a.body, { ControllerIdxSigs: sign(a, [k0]) }),
            new Message(b.body, { ControllerIdxSigs: sign(b, [k1]) }),
          ]),
        { message: /ambiguous multi-AID stream, found 2 leaf AIDs/ },
      );
    });
  });
});
