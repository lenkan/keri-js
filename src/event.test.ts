import { beforeAll, expect, test } from "vitest";
import { incept } from "./event.ts";
import { MatterCode } from "./parser/codes.ts";
import { SaltyKey } from "./cesr/keys.ts";
import { ready } from "libsodium-wrappers-sumo";
import cesr from "./parser/cesr-encoding.ts";

beforeAll(async () => {
  await ready;
});

test("Incept", () => {
  const passcode = "CDEyMzQ1Njc4OWxtbm9aBc";
  const name = "alice";

  const salt = `${MatterCode.Salt_128}${passcode.slice(0, 22).padStart(22, "A")}`;
  const key0 = new SaltyKey({ salt, password: `${name}00` });
  const key1 = new SaltyKey({ salt, password: `${name}11` });

  const result = incept({
    kt: "1",
    k: [key0.publicKey],
    nt: "1",
    n: [key1.publicKeyDigest],
    bt: "1",
    b: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
  });

  expect(result).toEqual({
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

  const sig = key0.sign(new TextEncoder().encode(JSON.stringify(result)));
  const indexedSignature = cesr.index(sig, 0);

  expect(sig).toEqual("0BDa_HJysQv1K2UpwawrI93KjPA8VGuypzqNdV-h7p8_MC8MhRqV9Kaw6brkiqQehKrWyvYspufkqg1IVz0O9GoC");
  expect(indexedSignature).toEqual(
    "AADa_HJysQv1K2UpwawrI93KjPA8VGuypzqNdV-h7p8_MC8MhRqV9Kaw6brkiqQehKrWyvYspufkqg1IVz0O9GoC",
  );

  expect(cesr.deindex(indexedSignature)).toEqual({
    index: 0,
    value: "0BDa_HJysQv1K2UpwawrI93KjPA8VGuypzqNdV-h7p8_MC8MhRqV9Kaw6brkiqQehKrWyvYspufkqg1IVz0O9GoC",
  });
});
