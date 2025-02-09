import { test, describe, beforeEach } from "node:test";
import type { InceptEvent } from "./incept.ts";
import { incept } from "./incept.ts";
import cesr from "../parser/cesr-encoding.ts";
import { privateKey00, privateKey11 } from "../../fixtures/keys.ts";
import { MatterCode } from "../parser/codes.ts";
import { ed25519 } from "@noble/curves/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import assert from "node:assert";

describe("Transferable single sig AID", () => {
  let currentKey: string;
  let nextKey: string;
  let event: InceptEvent;

  beforeEach(() => {
    currentKey = cesr.encode(MatterCode.Ed25519, ed25519.getPublicKey(privateKey00));
    nextKey = cesr.encode(
      MatterCode.Blake3_256,
      blake3
        .create({ dkLen: 32 })
        .update(cesr.encode(MatterCode.Ed25519, ed25519.getPublicKey(privateKey11)))
        .digest(),
    );

    event = incept({
      kt: "1",
      k: [currentKey],
      nt: "1",
      n: [nextKey],
      bt: "1",
      b: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
    });
  });

  test("should create event with said", () => {
    assert.deepStrictEqual(event, {
      v: "KERI10JSON000159_",
      t: "icp",
      d: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
      i: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
      s: "0",
      kt: "1",
      k: ["DIyH3rzq2PIQCbvBkL5Mlk1oC3XtLw5sZvjeRIdlZETf"],
      nt: "1",
      n: ["ENjMMFdspI2HGfN_9fGX717d9VeygNr7UNAfK2fDGfyf"],
      bt: "1",
      b: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
      c: [],
      a: [],
    });
  });

  test("Should create indexed signature", () => {
    const raw = new TextEncoder().encode(JSON.stringify(event));
    const sig = cesr.sign(raw, privateKey00, "ed25519");
    const indexedSignature = cesr.index(sig, 0);

    assert.strictEqual(sig, "0BDa_HJysQv1K2UpwawrI93KjPA8VGuypzqNdV-h7p8_MC8MhRqV9Kaw6brkiqQehKrWyvYspufkqg1IVz0O9GoC");
    assert.strictEqual(
      indexedSignature,
      "AADa_HJysQv1K2UpwawrI93KjPA8VGuypzqNdV-h7p8_MC8MhRqV9Kaw6brkiqQehKrWyvYspufkqg1IVz0O9GoC",
    );

    assert.deepStrictEqual(cesr.deindex(indexedSignature), {
      index: 0,
      value: "0BDa_HJysQv1K2UpwawrI93KjPA8VGuypzqNdV-h7p8_MC8MhRqV9Kaw6brkiqQehKrWyvYspufkqg1IVz0O9GoC",
    });
  });
});

describe("Non-Transferable single sig AID", () => {
  const privateKey = Buffer.from("3c794df9d5e8546f1b800c8f7b27075313422859da43c923e4423e8b634c7c00", "hex");
  const publicKey = cesr.encode(MatterCode.Ed25519N, ed25519.getPublicKey(privateKey));
  let event: InceptEvent;

  beforeEach(() => {
    event = incept({
      kt: "1",
      k: [publicKey],
      nt: "0",
      n: [],
      bt: "0",
      b: [],
    });
  });

  test("Should create event", () => {
    assert.deepStrictEqual(event, {
      v: "KERI10JSON0000fd_",
      t: "icp",
      d: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      i: "BKN0Oz4YvfPgHUB79WKtIg8xeu4Y0P8lmJn_zCWksR9w",
      s: "0",
      kt: "1",
      k: ["BKN0Oz4YvfPgHUB79WKtIg8xeu4Y0P8lmJn_zCWksR9w"],
      nt: "0",
      n: [],
      bt: "0",
      b: [],
      c: [],
      a: [],
    });
  });

  test("Should create indexed signature", () => {
    const expected = "AADjncC4UZdYY413O2HwAeW8Q0hCe0tgkpNUqBbjgJnvKZ5mG3h2hnYTzwnO896ArtnKNSkIOikWjXy3NUPGFoEB";
    const actual = cesr.index(cesr.sign(new TextEncoder().encode(JSON.stringify(event)), privateKey, "ed25519"), 0);
    assert.strictEqual(actual, expected);
  });
});
