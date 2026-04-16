import assert from "node:assert/strict";
import { createReadStream } from "node:fs";
import { describe, test } from "node:test";
import { Message } from "../cesr/__main__.ts";
import { incept, interact, type KeyEvent, rotate } from "./key-event.ts";
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

describe("KeyEventLog", () => {
  test("append icp creates log at sequence 0", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const log = inceptLog(key0, key1);
    assert.equal(log.state.lastEvent.s, "0");
  });

  test("append icp throws on missing signatures", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const event = incept({ signingKeys: [key0.publicKey], nextKeys: [key1.publicKeyDigest] });
    assert.throws(() => KeyEventLog.empty().append(new Message(event.body)), {
      message: "Threshold not met: 0 weight provided, but 1 required",
    });
  });

  test("append ixn advances sequence", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const log = inceptLog(key0, key1);
    const event = interact(log.state, { data: { test: "data" } });
    const sigs = sign(event, [key0]);
    const log2 = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
    assert.equal(log2.state.lastEvent.s, "1");
  });

  test("append rot advances sequence and updates keys", () => {
    const key0 = generateKeyPair();
    const key1 = generateKeyPair();

    const log = inceptLog(key0, key1);
    const event = rotate(log.state, { signingKeys: [key1.publicKey], nextKeyDigests: [key0.publicKeyDigest] });
    const sigs = sign(event, [key0]);
    const log2 = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
    assert.equal(log2.state.lastEvent.s, "1");
    assert.deepEqual(log2.state.signingKeys, [key1.publicKey]);
  });

  test("fromAsync parses alice.cesr into a valid key event log", async () => {
    const stream = createReadStream(new URL("../../fixtures/alice.cesr", import.meta.url));
    const log = await KeyEventLog.parse(stream);

    assert.equal(log.events.length, 2);
    assert.equal(log.state.identifier, "EPoVUviPdemgkjAhPnp7Q0bvMutVyd9BdIOLlZR8UE1y");
    assert.equal(log.state.lastEvent.s, "1");
    assert.equal(log.state.lastEvent.d, "EIybyHwRGcth--_AiIO6SNN2-VSYZqezeEphEChn3XIM");
  });

  describe("allowPartiallySigned", () => {
    test("allows appending icp with no controller sigs", () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const event = incept({ signingKeys: [key0.publicKey], nextKeys: [key1.publicKeyDigest] });
      const log = KeyEventLog.empty().append(new Message(event.body), { allowPartiallySigned: true });
      assert.equal(log.state.lastEvent.s, "0");
    });

    test("still throws on cryptographically invalid controller sig", () => {
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
    test("allows appending witnessed icp with no witness sigs", () => {
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

    test("throws on missing witness sigs by default", () => {
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

    test("still throws on cryptographically invalid witness sig", () => {
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
});
