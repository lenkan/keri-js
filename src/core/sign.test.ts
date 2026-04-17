import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Indexer, Matter } from "../cesr/__main__.ts";
import { generateKeyPair } from "./keys.ts";
import { sign } from "./sign.ts";
import { verifyThreshold } from "./verify.ts";

describe(basename(import.meta.url), () => {
  const payload = new TextEncoder().encode("test message");

  describe("non-indexed", () => {
    test("should produce a signature that verifies against the key", () => {
      const { publicKey, privateKey } = generateKeyPair();
      const sig = sign(payload, { key: privateKey });
      const indexedSig = Indexer.convert(Matter.parse(sig), 0).text();
      const result = verifyThreshold(payload, { keys: [publicKey], sigs: [indexedSig], threshold: "1" });
      assert.deepEqual(result.ok, true);
    });

    test("should produce different signatures for different payloads", () => {
      const { privateKey } = generateKeyPair();
      const other = new TextEncoder().encode("other message");
      const sig1 = sign(payload, { key: privateKey });
      const sig2 = sign(other, { key: privateKey });
      assert.notStrictEqual(sig1, sig2);
    });
  });

  describe("indexed", () => {
    test("should produce a signature that verifies against the key at the given index", () => {
      const { publicKey, privateKey } = generateKeyPair();
      const sig = sign(payload, { key: privateKey, index: 0 });
      const result = verifyThreshold(payload, { keys: [publicKey], sigs: [sig], threshold: "1" });
      assert.deepEqual(result.ok, true);
    });

    test("should produce different signatures for different indices", () => {
      const { privateKey } = generateKeyPair();
      const sig0 = sign(payload, { key: privateKey, index: 0 });
      const sig1 = sign(payload, { key: privateKey, index: 1 });
      assert.notStrictEqual(sig0, sig1);
    });
  });
});
