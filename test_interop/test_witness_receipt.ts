import assert from "node:assert";
import test, { after, before } from "node:test";
import { submitToWitnesses } from "@keri-js/infra/http";
import { parse } from "cesr";
import { ed25519Signer, generateKeyPair, KeyEvent, signEvent } from "keri";
import { collectAsync, createController, type Endpoint, startKeripyWitness } from "./utils.ts";

let wan: Endpoint;
let wil: Endpoint;
let wes: Endpoint;
const abortController = new AbortController();

before(async () => {
  [wan, wil, wes] = await Promise.all([
    startKeripyWitness({ signal: abortController.signal }),
    startKeripyWitness({ signal: abortController.signal }),
    startKeripyWitness({ signal: abortController.signal }),
  ]);
});

after(() => {
  abortController.abort();
});

test("Create identifier with single witness", async () => {
  const controller = createController();
  await controller.introduce(wan.oobi);
  const state = await controller.incept({
    wits: [wan.aid],
    toad: 1,
  });

  const events = await controller.export(state.id);
  assert.equal(events.length, 1);
  assert.partialDeepStrictEqual(events[0]?.body, {
    i: state.id,
    b: [wan.aid],
  });

  const response = await fetch(`${wan.url}/oobi/${state.id}`);
  assert.equal(response.status, 200);
  assert(response.body, "Expected response body");

  const parsed = await collectAsync(parse(response.body));
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.body.i, state.id);
  assert.equal(parsed[0].attachments.ControllerIdxSigs.length, 1);
  assert.equal(parsed[0].attachments.WitnessIdxSigs.length, 1);
  assert.equal(parsed[0].attachments.NonTransReceiptCouples.length, 0);
});

test("Create identifier with two witnesses", async () => {
  const controller = createController();
  await controller.introduce(wan.oobi);
  await controller.introduce(wil.oobi);

  const state = await controller.incept({
    wits: [wan.aid, wil.aid],
    toad: 2,
  });

  const events = await controller.export(state.id);
  assert.equal(events.length, 1);
  assert.partialDeepStrictEqual(events[0]?.body, {
    i: state.id,
    b: [wan.aid, wil.aid],
  });

  const response2 = await fetch(`${wil.url}/oobi/${state.id}`);
  assert.equal(response2.status, 200);

  const response = await fetch(`${wan.url}/oobi/${state.id}`);
  assert.equal(response.status, 200);
});

test("Create identifier with three witnesses", async () => {
  const controller = createController();
  await controller.introduce(wan.oobi);
  await controller.introduce(wil.oobi);
  await controller.introduce(wes.oobi);

  const state = await controller.incept({
    wits: [wan.aid, wil.aid, wes.aid],
    toad: 3,
  });

  const events = await controller.export(state.id);
  assert.equal(events.length, 1);
  assert.partialDeepStrictEqual(events[0]?.body, {
    i: state.id,
    b: [wan.aid, wil.aid, wes.aid],
  });

  const response2 = await fetch(`${wil.url}/oobi/${state.id}`);
  assert.equal(response2.status, 200);

  const response1 = await fetch(`${wan.url}/oobi/${state.id}`);
  assert.equal(response1.status, 200);

  const response3 = await fetch(`${wes.url}/oobi/${state.id}`);
  assert.equal(response3.status, 200);
});

test("Single witness returns one witness receipt", async () => {
  const key = generateKeyPair();
  const next = generateKeyPair();

  const event = KeyEvent.incept({
    signingKeys: [key.publicKey],
    nextKeyDigests: [next.publicKeyDigest],
    backers: [wan.aid],
    backerThreshold: 1,
  });

  await signEvent(event, [ed25519Signer(key.privateKey)]);

  const wigs = await submitToWitnesses(event, [wan]);
  assert.strictEqual(wigs.length, 1);
  assert.ok(wigs[0].length > 0);
});

test("Two witnesses return two witness receipts", async () => {
  const key = generateKeyPair();
  const next = generateKeyPair();

  const event = KeyEvent.incept({
    signingKeys: [key.publicKey],
    nextKeyDigests: [next.publicKeyDigest],
    backers: [wan.aid, wil.aid],
    backerThreshold: 2,
  });

  await signEvent(event, [ed25519Signer(key.privateKey)]);

  const wigs = await submitToWitnesses(event, [wan, wil]);
  assert.strictEqual(wigs.length, 2);
  assert.ok(wigs.every((w) => w.length > 0));
});

test("Three witnesses return three witness receipts", async () => {
  const key = generateKeyPair();
  const next = generateKeyPair();

  const event = KeyEvent.incept({
    signingKeys: [key.publicKey],
    nextKeyDigests: [next.publicKeyDigest],
    backers: [wan.aid, wil.aid, wes.aid],
    backerThreshold: 3,
  });

  await signEvent(event, [ed25519Signer(key.privateKey)]);

  const wigs = await submitToWitnesses(event, [wan, wil, wes]);
  assert.strictEqual(wigs.length, 3);
  assert.ok(wigs.every((w) => w.length > 0));
});
