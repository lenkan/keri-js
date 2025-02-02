import { test } from "node:test";
import { decrypt, encrypt } from "./encrypt.ts";
import assert from "node:assert";

test("derive key", async () => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const message = encoder.encode("hello world!");

  const result = await encrypt("password", message);
  const result2 = await decrypt("password", result);

  assert.equal(decoder.decode(result2), "hello world!");
});
