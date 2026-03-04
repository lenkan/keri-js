import { before, beforeEach, describe, test } from "node:test";
import assert from "node:assert";
import { Controller } from "../src/controller/controller.ts";
import { resolveWitness, type Witness } from "./utils.ts";
import { DatabaseSync } from "node:sqlite";
import { SqliteControllerStorage } from "#keri/sqlite-storage";

let controller: Controller;
let wan: Witness;
let wil: Witness;
let wes: Witness;

before(async () => {
  wan = await resolveWitness("http://localhost:5642");
  wil = await resolveWitness("http://localhost:5643");
  wes = await resolveWitness("http://localhost:5644");
});

beforeEach(async () => {
  const storage = new SqliteControllerStorage(new DatabaseSync(":memory:"));
  controller = new Controller({ storage });
});

describe("Create identifier", () => {
  test("Create identifier", async () => {
    const state = await controller.incept();

    const events = await controller.export(state.id);

    assert.equal(events.length, 1);
    assert.partialDeepStrictEqual(events[0]?.body, {
      i: state.id,
      b: [],
    });
  });

  test("Create identifier with single witness", async () => {
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
  });

  test("Create identifier with two witnesses", async () => {
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
});
