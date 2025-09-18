import { beforeEach, describe, test } from "node:test";
import assert from "node:assert";
import { Controller, KeyStore, PassphraseEncrypter } from "../src/main.ts";
import { SqliteStorage } from "../src/db/storage-sqlite.ts";

const wan: Witness = {
  oobi: "http://localhost:5642/oobi",
  url: "http://localhost:5642",
  aid: "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
};

const wil: Witness = {
  oobi: "http://localhost:5643/oobi",
  url: "http://localhost:5643",
  aid: "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
};

const wes: Witness = {
  oobi: "http://localhost:5644/oobi",
  url: "http://localhost:5644",
  aid: "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
};

interface Witness {
  aid: string;
  url: string;
  oobi: string;
}

let storage: SqliteStorage;
let controller: Controller;
let keystore: KeyStore;

beforeEach(() => {
  storage = new SqliteStorage();
  keystore = new KeyStore({
    encrypter: new PassphraseEncrypter("password"),
    storage,
  });
  controller = new Controller({ storage, keystore });

  storage.init();
});

describe("Create identifier", () => {
  test("Create identifier", async () => {
    const state = await controller.createIdentifier();
    const events = await controller.listEvents(state.i);

    assert.equal(events.length, 1);
    assert.partialDeepStrictEqual(events[0]?.event, {
      i: state.i,
      b: [],
    });
  });

  test("Create identifier with single witness", async () => {
    await controller.resolve(wan.oobi);
    const state = await controller.createIdentifier({ wits: [wan.aid] });

    const events = await controller.listEvents(state.i);
    assert.equal(events.length, 1);
    assert.partialDeepStrictEqual(events[0]?.event, {
      i: state.i,
      b: [wan.aid],
    });

    const response = await fetch(`${wan.url}/oobi/${state.i}`);
    assert.equal(response.status, 200);
  });

  test("Create identifier with two witnesses", async () => {
    await controller.resolve(wan.oobi);
    await controller.resolve(wil.oobi);

    const state = await controller.createIdentifier({ wits: [wan.aid, wil.aid], toad: 2 });

    const events = await controller.listEvents(state.i);
    assert.equal(events.length, 1);
    assert.partialDeepStrictEqual(events[0]?.event, {
      i: state.i,
      b: [wan.aid, wil.aid],
    });

    const response2 = await fetch(`${wil.url}/oobi/${state.i}`);
    assert.equal(response2.status, 200);

    const response = await fetch(`${wan.url}/oobi/${state.i}`);
    assert.equal(response.status, 200);
  });

  test("Create identifier with three witnesses", async () => {
    await controller.resolve(wan.oobi);
    await controller.resolve(wil.oobi);
    await controller.resolve(wes.oobi);

    const state = await controller.createIdentifier({ wits: [wan.aid, wil.aid, wes.aid], toad: 3 });

    const events = await controller.listEvents(state.i);
    assert.equal(events.length, 1);
    assert.partialDeepStrictEqual(events[0]?.event, {
      i: state.i,
      b: [wan.aid, wil.aid, wes.aid],
    });

    const response2 = await fetch(`${wil.url}/oobi/${state.i}`);
    assert.equal(response2.status, 200);

    const response1 = await fetch(`${wan.url}/oobi/${state.i}`);
    assert.equal(response1.status, 200);

    const response3 = await fetch(`${wes.url}/oobi/${state.i}`);
    assert.equal(response3.status, 200);
  });
});
