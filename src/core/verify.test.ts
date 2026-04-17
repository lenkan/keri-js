import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeyPair, type KeyPair } from "./keys.ts";
import { sign } from "./sign.ts";
import { verifyThreshold, verifyThresholdOrThrow } from "./verify.ts";

function generateKeys(count: number): KeyPair[] {
  const keys: KeyPair[] = [];
  for (let i = 0; i < count; i++) {
    keys.push(generateKeyPair());
  }
  return keys;
}

describe("verifyThreshold", () => {
  const payload = new TextEncoder().encode("test message");
  const keys = generateKeys(3);

  test("returns ok for a single valid signature", () => {
    const sigs = [sign(payload, { key: keys[0].privateKey, index: 0 })];
    assert.deepEqual(verifyThreshold(payload, { threshold: "1", keys: [keys[0].publicKey], sigs }), { ok: true });
  });

  test("returns ok when exactly enough signatures meet the threshold", () => {
    const sigs = [
      sign(payload, { key: keys[0].privateKey, index: 0 }),
      sign(payload, { key: keys[2].privateKey, index: 2 }),
    ];
    assert.deepEqual(verifyThreshold(payload, { threshold: "2", keys: keys.map((k) => k.publicKey), sigs }), {
      ok: true,
    });
  });

  test("returns error when no signatures are provided", () => {
    const key = generateKeyPair();
    const result = verifyThreshold(payload, { threshold: "1", keys: [key.publicKey], sigs: [] });
    assert.deepEqual(result, { ok: false, error: "Threshold not met: 0 weight provided, but 1 required" });
  });

  test("returns error when too few signatures are provided", () => {
    const sigs = [sign(payload, { key: keys[0].privateKey, index: 0 })];
    const result = verifyThreshold(payload, { threshold: "2", keys: [keys[0].publicKey, keys[1].publicKey], sigs });
    assert.deepEqual(result, { ok: false, error: "Threshold not met: 1 weight provided, but 2 required" });
  });

  test("returns error when signature does not match key", () => {
    const wrongSig = sign(payload, { key: keys[1].privateKey, index: 0 });
    const result = verifyThreshold(payload, { threshold: "1", keys: [keys[0].publicKey], sigs: [wrongSig] });
    assert.deepEqual(result, { ok: false, error: "Invalid signature for key at index 0" });
  });

  test("returns error when payload has been tampered with", () => {
    const tampered = new TextEncoder().encode("tampered message");
    const sigs = [sign(payload, { key: keys[0].privateKey, index: 0 })];
    const result = verifyThreshold(tampered, { threshold: "1", keys: [keys[0].publicKey], sigs });
    assert.deepEqual(result, { ok: false, error: "Invalid signature for key at index 0" });
  });

  test("returns ok for fractional threshold when combined weight is sufficient", () => {
    const sigs = [
      sign(payload, { key: keys[0].privateKey, index: 0 }),
      sign(payload, { key: keys[1].privateKey, index: 1 }),
    ];
    assert.deepEqual(
      verifyThreshold(payload, { threshold: ["1/2", "1/2"], keys: [keys[0].publicKey, keys[1].publicKey], sigs }),
      { ok: true },
    );
  });

  test("returns error for fractional threshold when weight is insufficient", () => {
    const sigs = [sign(payload, { key: keys[0].privateKey, index: 0 })];
    const result = verifyThreshold(payload, {
      threshold: ["1/2", "1/2"],
      keys: [keys[0].publicKey, keys[1].publicKey],
      sigs,
    });
    assert.equal(result.ok, false);
  });
});

describe("verifyThresholdOrThrow", () => {
  const key = generateKeyPair();
  const payload = new TextEncoder().encode("test message");

  test("does not throw for a valid signature", () => {
    const sigs = [sign(payload, { key: key.privateKey, index: 0 })];
    assert.doesNotThrow(() => verifyThresholdOrThrow(payload, { threshold: "1", keys: [key.publicKey], sigs }));
  });

  test("throws with the error message on failure", () => {
    assert.throws(() => verifyThresholdOrThrow(payload, { threshold: "1", keys: [key.publicKey], sigs: [] }), {
      message: "Threshold not met: 0 weight provided, but 1 required",
    });
  });
});
