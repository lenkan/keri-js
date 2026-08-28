import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { signWith as sign } from "../../test_utils/signing.ts";
import { Message } from "../cesr/main.ts";
import { generateKeyPair, type KeyPair } from "../keys/main.ts";
import {
  attachSourceSeal,
  backersFor,
  delegatedIncept,
  delegatedRotate,
  incept,
  interact,
  keyEventSeal,
  rotate,
} from "./key-event.ts";
import { KeyEventLog } from "./log.ts";

function inceptLog(key: KeyPair, nextKey: KeyPair): KeyEventLog {
  const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [nextKey.publicKeyDigest] });
  const sigs = sign(event, [key]);
  return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
}

describe(basename(import.meta.url), () => {
  describe("constructor", () => {
    test("should return the event body", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [] });
      assert.equal(event.body.t, "icp");
      assert.equal(event.body.k[0], key.publicKey);
    });

    test("should return non-empty raw Uint8Array", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [] });
      assert.ok(event.raw instanceof Uint8Array);
      assert.ok(event.raw.length > 0);
    });

    test("should encode the body in raw bytes", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [] });
      const text = new TextDecoder().decode(event.raw);
      assert.ok(text.includes(key.publicKey));
    });
  });

  describe("incept", () => {
    test("should throw when no keys are provided", () => {
      assert.throws(() => incept({ signingKeys: [], nextKeyDigests: [] }), {
        message: "No keys provided in inception event",
      });
    });

    test("should have correct fields in spec order for transferable single-sig AID", () => {
      const key0 = generateKeyPair({ insecureSeed: "key0" });
      const key1 = generateKeyPair({ insecureSeed: "key1" });
      const event = incept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        backerThreshold: 1,
        backers: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
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

    test("should have correct fields in spec order for non-transferable single-sig AID", () => {
      const ntKey = generateKeyPair({ insecureSeed: "ntKey", nonTransferable: true });
      const event = incept({ signingKeys: [ntKey.publicKey], nextKeyDigests: [] });

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

    test("should default toad to 0 with no witnesses", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [] });
      assert.equal(event.body.bt, "0");
    });

    test("should default toad to 1 with one witness", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({
        signingKeys: [key.publicKey],
        nextKeyDigests: [],
        backers: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM"],
      });
      assert.equal(event.body.bt, "1");
    });

    test("should default toad to all three with three witnesses", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({
        signingKeys: [key.publicKey],
        nextKeyDigests: [],
        backers: [
          "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
          "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
          "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
        ],
      });
      assert.equal(event.body.bt, "3");
    });

    test("should override default toad when explicitly set", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({
        signingKeys: [key.publicKey],
        nextKeyDigests: [],
        backers: ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM", "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"],
        backerThreshold: 0,
      });
      assert.equal(event.body.bt, "0");
    });

    test("should default the thresholds to every key", () => {
      const keys = ["k0", "k1", "k2"].map((seed) => generateKeyPair({ insecureSeed: seed }));
      const event = incept({
        signingKeys: keys.map((key) => key.publicKey),
        nextKeyDigests: keys.map((key) => key.publicKeyDigest),
      });
      assert.equal(event.body.kt, "3");
      assert.equal(event.body.nt, "3");
    });

    test("should use the given thresholds", () => {
      const keys = ["k0", "k1", "k2"].map((seed) => generateKeyPair({ insecureSeed: seed }));
      const event = incept({
        signingKeys: keys.map((key) => key.publicKey),
        signingThreshold: "2",
        nextKeyDigests: keys.map((key) => key.publicKeyDigest),
        nextThreshold: ["1/2", "1/2", "1/2"],
      });
      assert.equal(event.body.kt, "2");
      assert.deepEqual(event.body.nt, ["1/2", "1/2", "1/2"]);
    });

    test("should write a threshold of ten as hex", () => {
      const keys = Array.from({ length: 10 }, (_, i) => generateKeyPair({ insecureSeed: `k${i}` }));
      const event = incept({
        signingKeys: keys.map((key) => key.publicKey),
        nextKeyDigests: keys.map((key) => key.publicKeyDigest),
      });
      assert.equal(event.body.kt, "a");
      assert.equal(event.body.nt, "a");
    });

    test("should have fields in spec order", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const next = generateKeyPair({ insecureSeed: "k1" });
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });
      assert.deepEqual(Object.keys(event.body), ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"]);
    });

    test("should have equal d and i for self-addressing AID", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const next = generateKeyPair({ insecureSeed: "k1" });
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });
      const body = event.body;
      assert.equal(body.d, body.i);
    });

    test("should default to no config traits", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [] });
      assert.deepEqual(event.body.c, []);
    });

    test("should write the given config traits", () => {
      const key = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({ signingKeys: [key.publicKey], nextKeyDigests: [], configTraits: ["EO", "DND"] });
      assert.deepEqual(event.body.c, ["EO", "DND"]);
    });
  });

  describe("interact", () => {
    test("should produce correct field order", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.deepEqual(Object.keys(event.body), ["v", "t", "d", "i", "s", "p", "a"]);
    });

    test("should increment sequence number", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.equal(event.body.s, "1");
    });

    test("should reference prior event digest", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.equal(event.body.p, log.state.lastEvent.d);
    });

    test("should match identifier from state", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.equal(event.body.i, log.state.identifier);
    });

    test("should produce empty a field without data", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      const event = interact(log.state);
      assert.deepEqual(event.body.a, []);
    });

    test("should wrap data in a field array", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      const anchor = { i: "EFoo", s: "0", d: "EBar" };
      const event = interact(log.state, { data: anchor });
      assert.deepEqual(event.body.a, [anchor]);
    });

    test("should increment sequence correctly for chained interactions", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
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
    test("should produce correct fields in spec order", () => {
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
        removeBackers: ["BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],
        addBackers: ["BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo", "BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW"],
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
        "a",
      ]);
      assert.deepStrictEqual(event.body, {
        v: event.body.v,
        t: "rot",
        d: event.body.d,
        i: "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB",
        s: "2",
        p: "EDeCPBTHAt75Acgi9PfEciHFnc1r2DKAno3s9_QIYrXk",
        kt: "3",
        k: event.body.k,
        nt: "3",
        n: event.body.n,
        // One backer cut and two added leaves two, and KERI's threshold for two is both.
        bt: "2",
        br: ["BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"],
        ba: ["BO3cCAfQiqndZBBxwNk6RGkyA-OA1XbZhBj3s4-VIsCo", "BPowpltoeF14nMbU1ng89JSoYf3AmWhZ50KaCaVO6SIW"],
        a: [
          {
            i: "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur",
            s: "1",
            d: "ENl9GdcDY-4hlg5GtVwOg2E9X7JHw-7Dr5Zq5KNirISF",
          },
        ],
      });
    });

    test("should throw when state has no next key digest", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const event = incept({ signingKeys: [key0.publicKey], nextKeyDigests: [] });
      const sigs = sign(event, [key0]);
      const log = KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));

      assert.throws(() => rotate(log.state, { signingKeys: [key0.publicKey], nextKeyDigests: [] }), {
        message: /does not contain pre-committed next key digest/,
      });
    });

    test("should increment sequence from lastEvent", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const key2 = generateKeyPair({ insecureSeed: "k2" });
      const log = inceptLog(key0, key1);
      const event = rotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [key2.publicKeyDigest],
      });
      assert.equal(event.body.s, "1");
      assert.equal(event.body.p, log.state.lastEvent.d);
    });

    test("should use the given thresholds", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const key2 = generateKeyPair({ insecureSeed: "k2" });
      const log = inceptLog(key0, key1);
      const event = rotate(log.state, {
        signingKeys: [key1.publicKey],
        signingThreshold: "1",
        nextKeyDigests: [key2.publicKeyDigest],
        nextThreshold: ["1"],
      });
      assert.equal(event.body.kt, "1");
      assert.deepEqual(event.body.nt, ["1"]);
    });

    test("should carry the backer threshold forward when nothing changes", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const key2 = generateKeyPair({ insecureSeed: "k2" });
      const backers = ["BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM", "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"];

      const icp = incept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        backers,
      });
      const log = KeyEventLog.empty().append(new Message(icp.body, { ControllerIdxSigs: sign(icp, [key0]) }), {
        allowPartiallyWitnessed: true,
      });

      const event = rotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [key2.publicKeyDigest],
      });
      assert.equal(event.body.bt, "2");
    });
  });

  describe("delegatedIncept", () => {
    const delegator = "EAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    test("should throw when no keys are provided", () => {
      assert.throws(() => delegatedIncept({ signingKeys: [], nextKeyDigests: [], delegator }), {
        message: "No keys provided in inception event",
      });
    });

    test("should produce t=dip with di field", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const event = delegatedIncept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        delegator,
      });
      assert.equal(event.body.t, "dip");
      assert.equal(event.body.di, delegator);
    });

    test("should have fields in spec order ending with di", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const event = delegatedIncept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        delegator,
      });
      assert.deepEqual(Object.keys(event.body), [
        "v",
        "t",
        "d",
        "i",
        "s",
        "kt",
        "k",
        "nt",
        "n",
        "bt",
        "b",
        "c",
        "a",
        "di",
      ]);
    });

    test("should have equal d and i for self-addressing delegated AID", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const event = delegatedIncept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        delegator,
      });
      assert.equal(event.body.d, event.body.i);
    });

    test("should write the given config traits", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const event = delegatedIncept({
        signingKeys: [key0.publicKey],
        nextKeyDigests: [key1.publicKeyDigest],
        configTraits: ["DND"],
        delegator,
      });
      assert.deepEqual(event.body.c, ["DND"]);
    });
  });

  describe("delegatedRotate", () => {
    const delegator = "EAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    function delegatedInceptLog(key: KeyPair, nextKey: KeyPair): KeyEventLog {
      const event = delegatedIncept({
        signingKeys: [key.publicKey],
        nextKeyDigests: [nextKey.publicKeyDigest],
        delegator,
      });
      const sigs = sign(event, [key]);
      return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sigs }));
    }

    test("should throw when state has no delegator", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      assert.throws(
        () =>
          delegatedRotate(log.state, {
            signingKeys: [key1.publicKey],
            nextKeyDigests: [key0.publicKeyDigest],
          }),
        { message: /has no delegator/ },
      );
    });

    test("should produce t=drt without restating the delegator", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const key2 = generateKeyPair({ insecureSeed: "k2" });
      const log = delegatedInceptLog(key0, key1);
      const event = delegatedRotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [key2.publicKeyDigest],
      });
      assert.equal(event.body.t, "drt");
      assert.equal(event.body.s, "1");
      assert.equal(event.body.p, log.state.lastEvent.d);

      // v1 gives drt the same fields as rot; the delegator is established by the dip.
      assert.ok(!("di" in event.body));
    });

    test("should carry the delegator into the state a drt settles", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const key2 = generateKeyPair({ insecureSeed: "k2" });
      const log = delegatedInceptLog(key0, key1);
      const event = delegatedRotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [key2.publicKeyDigest],
      });
      const sigs = sign(event, [key1]);
      const rotated = log.append(new Message(event.body, { ControllerIdxSigs: sigs }));

      assert.equal(rotated.state.delegator, delegator);
    });

    test("should have fields in spec order", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const key2 = generateKeyPair({ insecureSeed: "k2" });
      const log = delegatedInceptLog(key0, key1);
      const event = delegatedRotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [key2.publicKeyDigest],
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
        "a",
      ]);
    });
  });

  describe("seals", () => {
    test("should build a key event seal from the event it commits to", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      const event = interact(log.state);

      assert.deepEqual(keyEventSeal(event), { i: event.body.i, s: event.body.s, d: event.body.d });
    });

    test("should attach a source couple naming the anchoring event, not the anchored one", () => {
      const key0 = generateKeyPair({ insecureSeed: "k0" });
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = inceptLog(key0, key1);
      const anchoring = interact(log.state, { data: { hello: "world" } });
      const anchored = incept({ signingKeys: [key1.publicKey], nextKeyDigests: [] });

      attachSourceSeal(anchored, anchoring);

      assert.deepEqual(anchored.attachments.SealSourceCouples, [{ snu: anchoring.body.s, digest: anchoring.body.d }]);
    });
  });

  describe("backersFor", () => {
    const witnesses = ["BAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "BAbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"];
    const added = "BAcccccccccccccccccccccccccccccccccccccccccc";

    function backeredLog(key: KeyPair, nextKey: KeyPair): KeyEventLog {
      const event = incept({
        signingKeys: [key.publicKey],
        nextKeyDigests: [nextKey.publicKeyDigest],
        backers: witnesses,
        backerThreshold: 0,
      });
      return KeyEventLog.empty().append(new Message(event.body, { ControllerIdxSigs: sign(event, [key]) }));
    }

    test("should take an inception's backers from the event itself", () => {
      const event = incept({ signingKeys: [generateKeyPair().publicKey], nextKeyDigests: [], backers: witnesses });

      assert.deepEqual(backersFor(event, null), witnesses);
    });

    test("should throw for a non-inception without key state", () => {
      const log = backeredLog(generateKeyPair({ insecureSeed: "k0" }), generateKeyPair({ insecureSeed: "k1" }));

      assert.throws(() => backersFor(interact(log.state), null), { message: /come from the key state/ });
    });

    test("should carry the backer set through an interaction", () => {
      const log = backeredLog(generateKeyPair({ insecureSeed: "k0" }), generateKeyPair({ insecureSeed: "k1" }));

      assert.deepEqual(backersFor(interact(log.state), log.state), witnesses);
    });

    // A rotation is receipted by the set it establishes, not the one it replaces, so the surviving
    // witness moves to index 0.
    test("should give a rotation the backer set it establishes", () => {
      const key1 = generateKeyPair({ insecureSeed: "k1" });
      const log = backeredLog(generateKeyPair({ insecureSeed: "k0" }), key1);
      const event = rotate(log.state, {
        signingKeys: [key1.publicKey],
        nextKeyDigests: [],
        removeBackers: [witnesses[0]],
        addBackers: [added],
      });

      assert.deepEqual(backersFor(event, log.state), [witnesses[1], added]);
    });
  });
});
