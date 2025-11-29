import { test, describe, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { formatDate, keri, type KeyEvent, saidify, type InceptEvent } from "./events.ts";
import { privateKey00, privateKey11 } from "../../fixtures/keys.ts";
import { type Key, KeyManager } from "../keystore/key-manager.ts";
import { MapStore } from "../main.ts";
import { cesr, Matter } from "cesr";

describe("Incept event", () => {
  describe("Input validation", () => {
    test("Should throw when no keys are provided", () => {
      assert.throws(() => keri.incept({ k: [], kt: "0", n: [], nt: "0" }), {
        message: "No keys provided in inception event",
      });
    });
  });

  describe("Transferable single sig AID", () => {
    const keyManager = new KeyManager({
      storage: new MapStore(),
      encrypter: { decrypt: async (x) => x, encrypt: async (x) => x },
    });

    let key: Key;
    let event: KeyEvent;

    beforeEach(async () => {
      key = await keyManager.import(privateKey00, privateKey11);

      event = keri.incept({
        kt: "1",
        k: [key.current],
        nt: "1",
        n: [key.next],
        bt: "1",
        b: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
      });
    });

    test("Should have correct order of fields", () => {
      assert.deepEqual(Object.keys(event), ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"]);
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
  });

  describe("Non-Transferable single sig AID", () => {
    const privateKey = Buffer.from("3c794df9d5e8546f1b800c8f7b27075313422859da43c923e4423e8b634c7c00", "hex");
    const publicKey = cesr.crypto.ed25519N(ed25519.getPublicKey(privateKey)).text();
    let event: InceptEvent;

    beforeEach(() => {
      event = keri.incept({
        kt: "1",
        k: [publicKey],
        nt: "0",
        n: [],
        bt: "0",
        b: [],
      });
    });

    test("Should create event", () => {
      assert.deepEqual(event, {
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
  });
});

describe("Registry", () => {
  test("Should create registry incept event", () => {
    const event = keri.registry({
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.partialDeepStrictEqual(event, {
      v: "KERI10JSON0000ff_",
      t: "vcp",
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.deepEqual(Object.keys(event), ["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"]);
    assert.equal(event.i, event.d);
    assert.equal(event.n.slice(0, 2), "0A");
  });

  test("Should set NB (no backer) configuration", () => {
    const event = keri.registry({
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.deepEqual(event.c, ["NB"]);
  });

  test("Should generate salt for registry event", () => {
    const event = keri.registry({
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    const salt = Matter.parse(event.n);

    assert.strictEqual(salt.code, Matter.Code.Salt_128);
  });

  test("Should create issuance event", () => {
    const event = keri.issue({
      i: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      ri: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.partialDeepStrictEqual(event, {
      v: "KERI10JSON0000ed_",
      t: "iss",
      i: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      ri: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });
  });
});

describe("Exchange event", () => {
  test("Should create exchange event", () => {
    const dt = formatDate(new Date());
    const event = keri.exchange({
      i: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      r: "EFAWQA1ktXrt5BFptVJrx6zKT8n6UIqU1XDP0tSB6yUS",
      dt,
    });

    assert.partialDeepStrictEqual(event, {
      t: "exn",
    });
    assert.deepStrictEqual(event.e, {});
  });
});

describe("Credential event", () => {
  test("Saidify rules", () => {
    const result = saidify(
      {
        d: "#".repeat(44),
        usageDisclaimer: {
          l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
        },
        issuanceDisclaimer: {
          l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
        },
      },
      ["d"],
    );

    assert.strictEqual(result.d, "EGZ97EjPSINR-O-KHDN_uw4fdrTxeuRXrqT5ZHHQJujQ");
  });

  test("Should create credential event", () => {
    const event = keri.credential({
      i: "EAK1H-RJM-mRzgNa7oNTv71FBvJERCHLunYI9ja9KW7w",
      ri: "EEXV71avZSL6fKJnQky_oxHqRPlNYR3zNGD-OpJe0DJa",
      s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      a: {
        i: "EOdUAG4xgTpDeV8eMf1aZuFmaSOjMvDRcdpvAO48TM9A",
        dt: "2025-04-17T21:53:17.019676+00:00",
        name: "John Doe",
      },
      r: {
        usageDisclaimer: {
          l: "Usage disclaimer",
        },
        issuanceDisclaimer: {
          l: "Issuance disclaimer",
        },
      },
    });

    assert.deepStrictEqual(Object.keys(event), ["v", "d", "i", "ri", "s", "a", "r"]);
    assert.deepStrictEqual(event, {
      v: "ACDC10JSON000221_",
      d: "EFkmdBxaS4m0IfUCtx8Lq2Ikk3xk_g0IPZbVLR7YwT5C",
      i: "EAK1H-RJM-mRzgNa7oNTv71FBvJERCHLunYI9ja9KW7w",
      ri: "EEXV71avZSL6fKJnQky_oxHqRPlNYR3zNGD-OpJe0DJa",
      s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      a: {
        d: "EPHGIjOSzWt8Uus-3jjWMgGG-2k_5sShSHRW3XVpYYBf",
        i: "EOdUAG4xgTpDeV8eMf1aZuFmaSOjMvDRcdpvAO48TM9A",
        dt: "2025-04-17T21:53:17.019676+00:00",
        name: "John Doe",
      },
      r: {
        d: "EDw7zqfJv_f4XdMyw5nHd7trK3PqAu-JMRThxGBxpccQ",
        usageDisclaimer: {
          l: "Usage disclaimer",
        },
        issuanceDisclaimer: {
          l: "Issuance disclaimer",
        },
      },
    });
  });
});
