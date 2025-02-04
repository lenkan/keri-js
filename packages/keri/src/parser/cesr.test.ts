import { test } from "node:test";
import assert from "node:assert";
import { ed25519 } from "@noble/curves/ed25519";
import cesr from "./cesr-encoding.ts";
import { MatterCode } from "./codes.ts";
import { privateKey00 } from "../../../../fixtures/keys.ts";

test("Salty key sign", () => {
  const message = new TextEncoder().encode("Hello, World!");

  const signature = cesr.sign(message, privateKey00, "ed25519");
  assert.strictEqual(
    signature,
    "0BCBzCGwWmngFqiaRxtsi9VYrONOZE76Zb2YRYdxAueT2sBFVzmIrvXtWdvDPlK7Ty9ypcwh0gKTXDzsZA5DyK0C",
  );
  const publicKey = cesr.encode(MatterCode.Ed25519, ed25519.getPublicKey(privateKey00));

  assert.strictEqual(cesr.verify(message, publicKey, signature), true);
});
