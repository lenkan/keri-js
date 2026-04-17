import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeyPair } from "./keys.ts";

describe("generateKeyPair", () => {
  test("returns a key pair with privateKey, publicKey, and publicKeyDigest", () => {
    const pair = generateKeyPair();
    assert.ok(pair.privateKey instanceof Uint8Array);
    assert.equal(pair.privateKey.length, 32);
    assert.equal(typeof pair.publicKey, "string");
    assert.equal(typeof pair.publicKeyDigest, "string");
  });

  test("returns a transferable public key (D prefix) by default", () => {
    const pair = generateKeyPair();
    assert.equal(pair.publicKey[0], "D");
    assert.equal(pair.publicKey.length, 44);
  });

  test("returns a non-transferable public key (B prefix) when nonTransferable is true", () => {
    const pair = generateKeyPair({ nonTransferable: true });
    assert.equal(pair.publicKey[0], "B");
    assert.equal(pair.publicKey.length, 44);
  });

  test("returns a deterministic key pair for the same seed", () => {
    const a = generateKeyPair({ seed: "test-seed" });
    const b = generateKeyPair({ seed: "test-seed" });
    assert.equal(a.publicKey, b.publicKey);
    assert.deepEqual(a.privateKey, b.privateKey);
    assert.equal(a.publicKeyDigest, b.publicKeyDigest);
  });

  test("returns different key pairs for different seeds", () => {
    const a = generateKeyPair({ seed: "seed-a" });
    const b = generateKeyPair({ seed: "seed-b" });
    assert.notEqual(a.publicKey, b.publicKey);
  });

  test("returns different key pairs on each call without a seed", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    assert.notEqual(a.publicKey, b.publicKey);
  });

  test("publicKeyDigest is a 44-character blake3_256 CESR string (E prefix)", () => {
    const pair = generateKeyPair({ seed: "digest-test" });
    assert.equal(pair.publicKeyDigest[0], "E");
    assert.equal(pair.publicKeyDigest.length, 44);
  });

  test("seed and nonTransferable can be combined", () => {
    const a = generateKeyPair({ seed: "my-seed", nonTransferable: true });
    const b = generateKeyPair({ seed: "my-seed", nonTransferable: true });
    assert.equal(a.publicKey[0], "B");
    assert.equal(a.publicKey, b.publicKey);
  });
});
