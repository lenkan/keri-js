import { test } from "node:test";
import { incept } from "./incept.ts";
import cesr from "../parser/cesr-encoding.ts";
import { privateKey00, privateKey11 } from "../../fixtures/keys.ts";
import { MatterCode } from "../parser/codes.ts";
import { ed25519 } from "@noble/curves/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import assert from "node:assert";

test("Incept", () => {
  const current = cesr.encode(MatterCode.Ed25519, ed25519.getPublicKey(privateKey00));

  const next = cesr.encode(
    MatterCode.Blake3_256,
    blake3
      .create({ dkLen: 32 })
      .update(cesr.encode(MatterCode.Ed25519, ed25519.getPublicKey(privateKey11)))
      .digest(),
  );

  const result = incept({
    kt: "1",
    k: [current],
    nt: "1",
    n: [next],
    bt: "1",
    b: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
  });

  assert.deepStrictEqual(result, {
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

  const sig = cesr.sign(new TextEncoder().encode(JSON.stringify(result)), privateKey00, "ed25519");
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
