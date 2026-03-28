import { beforeEach, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createReadStream } from "node:fs";
import { Message } from "cesr";
import { incept, interact, rotate, type KeyEvent } from "./key-event.ts";
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
  let key0: KeyPair;
  let key1: KeyPair;

  beforeEach(() => {
    key0 = generateKeyPair();
    key1 = generateKeyPair();
  });

  test("append icp creates log at sequence 0", () => {
    const log = inceptLog(key0, key1);
    assert.equal(log.state.lastEvent.s, "0");
  });

  test("append icp throws on missing signatures", () => {
    const event = incept({ signingKeys: [key0.publicKey], nextKeys: [key1.publicKeyDigest] });
    assert.throws(() => KeyEventLog.empty().append(new Message(event.body)), {
      message: "Threshold not met: 0 weight provided, but 1 required",
    });
  });

  test("append ixn advances sequence", () => {
    const log = inceptLog(key0, key1);
    const event = interact(log.state, { data: { test: "data" } });
    const sigs = sign(event, [key0]);
    const log2 = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
    assert.equal(log2.state.lastEvent.s, "1");
  });

  test("append rot advances sequence and updates keys", () => {
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
});
