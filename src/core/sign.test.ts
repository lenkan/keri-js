import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { Indexer, Matter } from "../cesr/__main__.ts";
import { generateKeyPair } from "./keys.ts";
import { sign } from "./sign.ts";
import { verify } from "./verify.ts";

describe("sign", () => {
  const payload = new TextEncoder().encode("test message");

  describe("non-indexed", () => {
    test("produces a signature that verifies against the key", () => {
      const { publicKey, privateKey } = generateKeyPair();
      const sig = sign(payload, { key: privateKey });
      const indexedSig = Indexer.convert(Matter.parse(sig), 0).text();
      const result = verify(payload, { keys: [publicKey], sigs: [indexedSig], threshold: "1" });
      assert.deepEqual(result.ok, true);
    });

    test("different payloads produce different signatures", () => {
      const { privateKey } = generateKeyPair();
      const other = new TextEncoder().encode("other message");
      const sig1 = sign(payload, { key: privateKey });
      const sig2 = sign(other, { key: privateKey });
      assert.notStrictEqual(sig1, sig2);
    });
  });

  describe("indexed", () => {
    test("produces a signature that verifies against the key at the given index", () => {
      const { publicKey, privateKey } = generateKeyPair();
      const sig = sign(payload, { key: privateKey, index: 0 });
      const result = verify(payload, { keys: [publicKey], sigs: [sig], threshold: "1" });
      assert.deepEqual(result.ok, true);
    });

    test("different indices produce different signatures", () => {
      const { privateKey } = generateKeyPair();
      const sig0 = sign(payload, { key: privateKey, index: 0 });
      const sig1 = sign(payload, { key: privateKey, index: 1 });
      assert.notStrictEqual(sig0, sig1);
    });
  });
});
