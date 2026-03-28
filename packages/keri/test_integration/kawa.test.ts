import { before, describe, test } from "node:test";
import assert from "node:assert";
import { sign, keri, submitToWitnesses } from "#keri";
import { resolveWitness, type Witness } from "./utils.ts";

let wan: Witness;
let wil: Witness;
let wes: Witness;

before(async () => {
  wan = await resolveWitness("http://localhost:5642");
  wil = await resolveWitness("http://localhost:5643");
  wes = await resolveWitness("http://localhost:5644");
});

describe("Keri Algorithm for Witness Agreement (KAWA)", () => {
  test("single witness returns one wig", async () => {
    const key = keri.utils.generateKeyPair();
    const next = keri.utils.generateKeyPair();

    const event = keri.incept({
      signingKeys: [key.publicKey],
      nextKeys: [next.publicKeyDigest],
      wits: [wan.aid],
      toad: 1,
    });

    event.attachments.ControllerIdxSigs.push(sign(event.raw, { key: key.privateKey, index: 0 }));

    const wigs = await submitToWitnesses(event, [wan]);
    assert.strictEqual(wigs.length, 1);
    assert.ok(wigs[0].length > 0);
  });

  test("two witnesses return two wigs", async () => {
    const key = keri.utils.generateKeyPair();
    const next = keri.utils.generateKeyPair();

    const event = keri.incept({
      signingKeys: [key.publicKey],
      nextKeys: [next.publicKeyDigest],
      wits: [wan.aid, wil.aid],
      toad: 2,
    });

    event.attachments.ControllerIdxSigs.push(sign(event.raw, { key: key.privateKey, index: 0 }));

    const wigs = await submitToWitnesses(event, [wan, wil]);
    assert.strictEqual(wigs.length, 2);
    assert.ok(wigs.every((w) => w.length > 0));
  });

  test("three witnesses return three wigs", async () => {
    const key = keri.utils.generateKeyPair();
    const next = keri.utils.generateKeyPair();

    const event = keri.incept({
      signingKeys: [key.publicKey],
      nextKeys: [next.publicKeyDigest],
      wits: [wan.aid, wil.aid, wes.aid],
      toad: 3,
    });

    event.attachments.ControllerIdxSigs.push(sign(event.raw, { key: key.privateKey, index: 0 }));

    const wigs = await submitToWitnesses(event, [wan, wil, wes]);
    assert.strictEqual(wigs.length, 3);
    assert.ok(wigs.every((w) => w.length > 0));
  });
});
