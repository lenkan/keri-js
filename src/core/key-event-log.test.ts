import assert from "node:assert/strict";
import { createReadStream } from "node:fs";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Message } from "../cesr/main.ts";
import { delegatedIncept, delegatedRotate, incept, interact, type KeyEvent, rotate } from "./key-event.ts";
import { KeyEventLog } from "./key-event-log.ts";
import { generateKeyPair, type KeyPair } from "./keys.ts";
import { sign as _sign } from "./sign.ts";

function sign(event: KeyEvent, keys: KeyPair[]): string[] {
  return keys.map((key, idx) => _sign(event.raw, { key: key.privateKey, index: idx }));
}

function inceptLog(key: KeyPair, nextKey: KeyPair): KeyEventLog {
  const event = incept({ signingKeys: [key.publicKey], nextKeys: [nextKey.publicKeyDigest] });
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

    const event = incept({ signingKeys: [key0.publicKey], nextKeys: [key1.publicKeyDigest] });
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
    const sigs = sign(event, [key0]);
    const log2 = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
    assert.equal(log2.state.lastEvent.s, "1");
    assert.deepEqual(log2.state.signingKeys, [key1.publicKey]);
  });

  test("should parse alice.cesr into a valid key event log", async () => {
    const stream = createReadStream(new URL("../../fixtures/alice.cesr", import.meta.url));
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
    const stream = createReadStream(new URL("../../fixtures/delegated.cesr", import.meta.url));

    const log = await KeyEventLog.parse(stream, { allowPartiallyWitnessed: true });

    assert.equal(log.state.identifier, delegateAid);
    assert.equal(log.state.delegator, delegatorAid);
    assert.equal(log.state.lastEvent.s, "0");
    assert.equal(log.events[0].body.t, "dip");

    assert.ok(log.delegator, "Expected a nested delegator KEL");
    assert.equal(log.delegator.state.identifier, delegatorAid);
    assert.ok(
      log.delegator.events.some((e) => e.body.t === "ixn"),
      "Expected delegator KEL to contain the anchoring ixn",
    );
  });

  describe("allowPartiallySigned", () => {
    test("should allow appending icp with no controller sigs", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const event = incept({ signingKeys: [key0.publicKey], nextKeys: [key1.publicKeyDigest] });
      const log = KeyEventLog.empty().append(new Message(event.body), { allowPartiallySigned: true });
      assert.equal(log.state.lastEvent.s, "0");
    });

    test("should still throw on cryptographically invalid controller sig", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const wrongKey = generateKeyPair();
      const event = incept({ signingKeys: [key0.publicKey], nextKeys: [key1.publicKeyDigest] });
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
        nextKeys: [key1.publicKeyDigest],
        wits: [witnessKey.publicKey],
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
        nextKeys: [key1.publicKeyDigest],
        wits: [witnessKey.publicKey],
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
        nextKeys: [key1.publicKeyDigest],
        wits: [witnessKey.publicKey],
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
        nextKeys: [nextKey.publicKeyDigest],
        delegator,
      });
      const sigs = sign(event, [key]);
      return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
    }

    test("should append dip and record delegator on state", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const log = dipLog(key0, key1);
      assert.equal(log.state.lastEvent.s, "0");
      assert.equal(log.state.delegator, delegator);
    });

    test("should accept dip without SealSourceCouple attachment", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const event = delegatedIncept({
        signingKeys: [key0.publicKey],
        nextKeys: [key1.publicKeyDigest],
        delegator,
      });
      const sigs = sign(event, [key0]);
      const log = KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
      assert.equal(log.state.delegator, delegator);
    });

    test("should accept dip with SealSourceCouple attachment", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const event = delegatedIncept({
        signingKeys: [key0.publicKey],
        nextKeys: [key1.publicKeyDigest],
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

    test("should reject dip with cryptographically invalid controller sig", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const wrongKey = generateKeyPair();
      const event = delegatedIncept({
        signingKeys: [key0.publicKey],
        nextKeys: [key1.publicKeyDigest],
        delegator,
      });
      const wrongSigs = sign(event, [wrongKey]);
      assert.throws(
        () =>
          KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: wrongSigs }), {
            allowPartiallySigned: true,
          }),
        { message: "Invalid signature for key at index 0" },
      );
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
      const sigs = sign(event, [key0]);
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
      const event = incept({ signingKeys: [key.publicKey], nextKeys: [nextKey.publicKeyDigest] });
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
        nextKeys: [delegateNext.publicKeyDigest],
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
        nextKeys: [delegateNext.publicKeyDigest],
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
        nextKeys: [delegateNext.publicKeyDigest],
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
        nextKeys: [delegateNext.publicKeyDigest],
        delegator: "EAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      });
      const dipSigs = sign(dip, [delegateKey]);

      assert.throws(
        () => KeyEventLog.empty().append(new Message(dip.body, { ControllerIdxSigs: dipSigs }), { delegator }),
        { message: /Delegation mismatch/ },
      );
    });

    test("should retain delegator across subsequent ixn/drt appends", () => {
      const delegatorKey = generateKeyPair();
      const delegatorNext = generateKeyPair();
      const delegateKey = generateKeyPair();
      const delegateNext = generateKeyPair();

      let delegator = makeDelegator(delegatorKey, delegatorNext);

      const dip = delegatedIncept({
        signingKeys: [delegateKey.publicKey],
        nextKeys: [delegateNext.publicKeyDigest],
        delegator: delegator.state.identifier,
      });
      delegator = anchorDip(delegator, delegatorKey, dip.body);

      const dipSigs = sign(dip, [delegateKey]);
      const dipLog = KeyEventLog.empty().append(new Message(dip.body, { ControllerIdxSigs: dipSigs }), { delegator });

      const ixn = interact(dipLog.state);
      const ixnSigs = sign(ixn, [delegateKey]);
      const after = dipLog.append(new Message(ixn.body, { ControllerIdxSigs: ixnSigs }));

      assert.ok(after.delegator, "Delegator should remain attached after ixn");
      assert.equal(after.delegator.state.identifier, delegator.state.identifier);
    });
  });
});
