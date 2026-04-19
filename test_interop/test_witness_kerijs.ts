import assert from "node:assert";
import test, { after, before } from "node:test";
import { parse } from "#keri/cesr";
import { collectAsync, createController, startKerijsWitness, type Witness } from "./utils.ts";

let wan: Witness;
let wil: Witness;

const abortController = new AbortController();

before(async () => {
  wan = await startKerijsWitness({ signal: abortController.signal });
  wil = await startKerijsWitness({ signal: abortController.signal });
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

  const response = await fetch(`${wan.url}/oobi/${state.id}`);
  assert.equal(response.status, 200);
  assert(response.body, "Expected response body");

  const parsed = await collectAsync(parse(response.body));
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.body.i, state.id);
  assert.equal(parsed[0].attachments.ControllerIdxSigs.length, 1);
  assert.equal(parsed[0].attachments.WitnessIdxSigs.length, 2);
  assert.equal(parsed[0].attachments.NonTransReceiptCouples.length, 0);
});
