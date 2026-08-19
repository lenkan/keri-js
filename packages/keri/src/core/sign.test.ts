import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeText, Indexer, Matter } from "cesr";
import { incept } from "./key-event.ts";
import { generateKeyPair } from "./keys.ts";
import { ed25519Signer, signEvent } from "./sign.ts";
import { verifyThreshold } from "./verify.ts";

describe(basename(import.meta.url), () => {
  const payload = new TextEncoder().encode("test message");

  describe("ed25519Signer", () => {
    test("should expose the public key matching the private key", async () => {
      const { publicKey, privateKey } = generateKeyPair();
      assert.equal(ed25519Signer(privateKey).publicKey, publicKey);
    });

    test("should produce a signature that verifies against the key", async () => {
      const { publicKey, privateKey } = generateKeyPair();
      const sig = await ed25519Signer(privateKey).sign(payload);
      const indexedSig = encodeText(Indexer.convert(Matter.parse(sig), 0));
      const result = verifyThreshold(payload, { keys: [publicKey], sigs: [indexedSig], threshold: "1" });
      assert.deepEqual(result.ok, true);
    });

    test("should produce different signatures for different payloads", async () => {
      const { privateKey } = generateKeyPair();
      const signer = ed25519Signer(privateKey);
      const other = new TextEncoder().encode("other message");
      assert.notStrictEqual(await signer.sign(payload), await signer.sign(other));
    });
  });

  describe("signEvent", () => {
    test("should attach one indexed signature per signer", async () => {
      const key0 = generateKeyPair();
      const key1 = generateKeyPair();
      const next = generateKeyPair();

      const event = incept({
        signingKeys: [key0.publicKey, key1.publicKey],
        nextKeyDigests: [next.publicKeyDigest],
      });

      await signEvent(event, [ed25519Signer(key0.privateKey), ed25519Signer(key1.privateKey)]);

      assert.equal(event.attachments.ControllerIdxSigs.length, 2);
      const result = verifyThreshold(event.raw, {
        keys: [key0.publicKey, key1.publicKey],
        sigs: event.attachments.ControllerIdxSigs,
        threshold: "2",
      });
      assert.deepEqual(result, { ok: true });
    });

    test("should append to signatures already attached", async () => {
      const key = generateKeyPair();
      const next = generateKeyPair();
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });

      await signEvent(event, [ed25519Signer(key.privateKey)]);
      await signEvent(event, [ed25519Signer(key.privateKey)]);

      assert.equal(event.attachments.ControllerIdxSigs.length, 2);
    });

    test("should return the same message so calls can be chained", async () => {
      const key = generateKeyPair();
      const next = generateKeyPair();
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });

      assert.equal(await signEvent(event, [ed25519Signer(key.privateKey)]), event);
    });
  });
});
