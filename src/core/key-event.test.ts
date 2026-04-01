import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { Message } from "../cesr/__main__.ts";
import { incept, interact, type KeyEvent, rotate } from "./key-event.ts";
import { KeyEventLog } from "./key-event-log.ts";
import { generateKeyPair, type KeyPair } from "./keys.ts";
import { sign as _sign } from "./sign.ts";

function sign(event: KeyEvent, keys: KeyPair[]): string[] {
  return keys.map((key, idx) => _sign(event.raw, { key: key.privateKey, index: idx }));
}

function inceptLog(key: KeyPair, nextKey: KeyPair): KeyEventLog {
  const event = incept({ signingKeys: [key.publicKey], nextKeys: [nextKey.publicKeyDigest] });
  const sigs = sign(event, [key]);
  return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
}

describe("KeyEvent", () => {
  describe("constructor", () => {
    test("body returns the event body", () => {
      const key = generateKeyPair("k0");
      const event = incept({ signingKeys: [key.publicKey], nextKeys: [] });
      assert.equal(event.body.t, "icp");
      assert.equal(event.body.k[0], key.publicKey);
    });

    test("raw returns non-empty Uint8Array", () => {
      const key = generateKeyPair("k0");
      const event = incept({ signingKeys: [key.publicKey], nextKeys: [] });
      assert.ok(event.raw instanceof Uint8Array);
      assert.ok(event.raw.length > 0);
    });

    test("raw bytes encode the body", () => {
      const key = generateKeyPair("k0");
      const event = incept({ signingKeys: [key.publicKey], nextKeys: [] });
      const text = new TextDecoder().decode(event.raw);
      assert.ok(text.includes(key.publicKey));
    });
  });

  describe("incept", () => {
    test("throws when no keys are provided", () => {
      assert.throws(() => incept({ signingKeys: [], nextKeys: [] }), {
        message: "No keys provided in inception event",
      });
    });

    test("transferable single-sig AID has correct fields in spec order", () => {
      const key0 = generateKeyPair("key0");
      const key1 = generateKeyPair("key1");
      const event = incept({
        signingKeys: [key0.publicKey],
        nextKeys: [key1.publicKeyDigest],
        toad: 1,
        wits: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
      });

      assert.deepStrictEqual(event.body, {
        v: "KERI10JSON000159_",
        t: "icp",
        d: "ELW8TdX4Q4Yh6wIB6wvjrHjmKl1qrg9HNpTy9t0GGFz3",
        i: "ELW8TdX4Q4Yh6wIB6wvjrHjmKl1qrg9HNpTy9t0GGFz3",
        s: "0",
        kt: "1",
        k: [key0.publicKey],
        nt: "1",
        n: [key1.publicKeyDigest],
        bt: "1",
        b: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
        c: [],
        a: [],
      });
    });

    test("non-transferable single-sig AID has correct fields in spec order", () => {
      const ntKey = generateKeyPair("ntKey", { nonTransferable: true });
      const event = incept({ signingKeys: [ntKey.publicKey], nextKeys: [] });

      assert.deepStrictEqual(event.body, {
        v: "KERI10JSON0000fd_",
        t: "icp",
        d: "EJgPJ5cprjecCiyymC9hv8ZornUdBbCH4kopcy3AgBvf",
        i: ntKey.publicKey,
        s: "0",
        kt: "1",
        k: [ntKey.publicKey],
        nt: "0",
        n: [],
        bt: "0",
        b: [],
        c: [],
        a: [],
      });
    });

    test("toad defaults to 0 with no witnesses", () => {
      const key = generateKeyPair("k0");
      const event = incept({ signingKeys: [key.publicKey], nextKeys: [] });
      assert.equal(event.body.bt, "0");
    });

    test("toad defaults to 1 with one witness", () => {
      const key = generateKeyPair("k0");
      const event = incept({
        signingKeys: [key.publicKey],
        nextKeys: [],
        wits: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
      });
      assert.equal(event.body.bt, "1");
    });

    test("toad defaults to n-1 with multiple witnesses", () => {
      const key = generateKeyPair("k0");
      const event = incept({
        signingKeys: [key.publicKey],
        nextKeys: [],
        wits: [
          "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
          "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
          "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
        ],
      });
      assert.equal(event.body.bt, "2");
    });

    test("explicit toad overrides default", () => {
      const key = generateKeyPair("k0");
      const event = incept({
        signingKeys: [key.publicKey],
        nextKeys: [],
        wits: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM", "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"],
        toad: 0,
      });
      assert.equal(event.body.bt, "0");
    });

    test("fields are in spec order", () => {
      const key = generateKeyPair("k0");
      const next = generateKeyPair("k1");
      const event = incept({ signingKeys: [key.publicKey], nextKeys: [next.publicKeyDigest] });
      assert.deepEqual(Object.keys(event.body), ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"]);
    });

    test("d and i are equal for transferable single-sig AID (self-addressing)", () => {
      const key = generateKeyPair("k0");
      const next = generateKeyPair("k1");
      const event = incept({ signingKeys: [key.publicKey], nextKeys: [next.publicKeyDigest] });
      const body = event.body;
      assert.equal(body.d, body.i);
    });
  });

  describe("interact", () => {
    test("produces correct field order", () => {
      const key0 = generateKeyPair("k0");
      const key1 = generateKeyPair("k1");
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.deepEqual(Object.keys(event.body), ["v", "t", "d", "i", "s", "p", "a"]);
    });

    test("increments sequence number", () => {
      const key0 = generateKeyPair("k0");
      const key1 = generateKeyPair("k1");
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.equal(event.body.s, "1");
    });

    test("references prior event digest", () => {
      const key0 = generateKeyPair("k0");
      const key1 = generateKeyPair("k1");
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.equal(event.body.p, log.state.lastEvent.d);
    });

    test("identifier matches state", () => {
      const key0 = generateKeyPair("k0");
      const key1 = generateKeyPair("k1");
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.equal(event.body.i, log.state.identifier);
    });

    test("without data produces empty a field", () => {
      const key0 = generateKeyPair("k0");
      const key1 = generateKeyPair("k1");
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.deepEqual(event.body.a, []);
    });

    test("with data wraps it in a field array", () => {
      const key0 = generateKeyPair("k0");
      const key1 = generateKeyPair("k1");
      const log = inceptLog(key0, key1);
      const anchor = { i: "EFoo", s: "0", d: "EBar" };
      const event = interact(log.state, { data: anchor });
      assert.deepEqual(event.body.a, [anchor]);
    });

    test("chained interactions increment sequence correctly", () => {
      const key0 = generateKeyPair("k0");
      const key1 = generateKeyPair("k1");
      let log = inceptLog(key0, key1);

      for (let i = 1; i <= 3; i++) {
        const event = interact(log.state);
        const sigs = sign(event, [key0]);
        log = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));
        assert.equal(log.state.lastEvent.s, i.toString(16));
      }
    });
  });

  describe("rotate", () => {
    test("produces correct fields in spec order", () => {
      const state = {
        identifier: "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        signingKeys: [
          "DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj",
          "DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz",
          "DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf",
        ],
        nextKeyDigests: [
          "EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe",
          "EERS8udHp2FW89nmaHweQWnZz7I8v9FTQdA-LZ_amqGh",
          "EAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTg",
        ],
        signingThreshold: "2",
        nextThreshold: "2",
        backers: ["BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],
        backerThreshold: "4",
        configTraits: [],
        lastEvent: {
          d: "EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk",
          s: "1",
          i: "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        },
        lastEstablishment: {
          d: "EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk",
          s: "1",
          i: "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        },
      };

      const event = rotate(state, {
        signingKeys: [
          "DLv9BlDvjcZWkfPfWcYhNK-xQxz89h82_wA184Vxk8dj",
          "DCx3WypeBym3fCkVizTg18qEThSrVnB63dFq2oX5c3mz",
          "DO0PG_ww4PbF2jUIxQnlb4DluJu5ndNehp0BTGWXErXf",
        ],
        nextKeyDigests: [
          "EA8_fj-Ezin_Us_gUcg5JQJkIIBnrcZt3HEIuH-E1lpe",
          "EERS8udHp2FW89nmaHweQWnZz7I8v9FTQdA-LZ_amqGh",
          "EAEzmrPusrj4CDKnSFQvhCEW6T95C7hBeFtZtRD7rOTg",
        ],
        br: ["BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],
        ba: ["BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo", "BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW"],
        data: {
          i: "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
          s: "1",
          d: "ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF",
        },
      });

      assert.deepEqual(Object.keys(event.body), [
        "v",
        "t",
        "d",
        "i",
        "s",
        "p",
        "kt",
        "k",
        "nt",
        "n",
        "bt",
        "br",
        "ba",
        "c",
        "a",
      ]);
      assert.deepStrictEqual(event.body, {
        v: event.body.v,
        t: "rot",
        d: event.body.d,
        i: "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        s: "2",
        p: "EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk",
        kt: "1",
        k: event.body.k,
        nt: "1",
        n: event.body.n,
        bt: "0",
        br: ["BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],
        ba: ["BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo", "BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW"],
        c: [],
        a: [
          {
            i: "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
            s: "1",
            d: "ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF",
          },
        ],
      });
    });

    test("throws when state has no next key digest", () => {
      const key0 = generateKeyPair("k0");
      const event = incept({ signingKeys: [key0.publicKey], nextKeys: [] });
      const sigs = sign(event, [key0]);
      const log = KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));

      assert.throws(() => rotate(log.state, { signingKeys: [key0.publicKey], nextKeyDigests: [] }), {
        message: /does not contain pre-committed next key digest/,
      });
    });

    test("increments sequence from lastEvent", () => {
      const key0 = generateKeyPair("k0");
      const key1 = generateKeyPair("k1");
      const key2 = generateKeyPair("k2");
      const log = inceptLog(key0, key1);
      const event = rotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [key2.publicKeyDigest],
      });
      assert.equal(event.body.s, "1");
      assert.equal(event.body.p, log.state.lastEvent.d);
    });
  });
});
