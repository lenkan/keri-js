import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeText, Indexer, Matter } from "../cesr/main.ts";
import { generateKeyPair } from "./keys.ts";
import { ed25519Signer } from "./signer.ts";
import { verifyThreshold } from "./verify.ts";

describe(basename(import.meta.url), () => {
  const payload = new TextEncoder().encode("test message");

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
});
