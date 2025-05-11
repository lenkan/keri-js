import { describe, test } from "node:test";
import assert from "node:assert";
import { PassphraseEncrypter } from "./encrypt.ts";

describe("Passphrase encrypter", () => {
  test("derive key", async () => {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const message = encoder.encode("hello world!");
    const enc = new PassphraseEncrypter("password");

    const result = await enc.encrypt(message);
    const result2 = await enc.decrypt(result);

    assert.equal(decoder.decode(result2), "hello world!");
  });
});
