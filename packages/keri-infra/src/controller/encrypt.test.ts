import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { PassphraseEncrypter } from "./encrypt.ts";

describe(basename(import.meta.url), () => {
  test("should encrypt and decrypt successfully", async () => {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const message = encoder.encode("hello world!");
    const enc = new PassphraseEncrypter("password");

    const result = await enc.encrypt(message);
    const result2 = await enc.decrypt(result);

    assert.equal(decoder.decode(result2), "hello world!");
  });

  test("should throw error on wrong password", async () => {
    const encoder = new TextEncoder();
    const enc = new PassphraseEncrypter("password");

    const result = await enc.encrypt(encoder.encode("hello world!"));
    const enc2 = new PassphraseEncrypter("wrong password");

    await assert.rejects(() => enc2.decrypt(result), {
      name: "Error",
      message: "Could not decrypt data",
    });
  });

  test("should throw error on malformed payload", async () => {
    const enc = new PassphraseEncrypter("password");

    await assert.rejects(() => enc.decrypt(new Uint8Array([1, 2, 3])), {
      name: "Error",
      message: "Invalid encrypted payload",
    });
  });
});
