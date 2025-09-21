import { beforeEach, describe, test } from "node:test";
import assert from "node:assert";
import { Controller, KeyManager, PassphraseEncrypter } from "../src/main.ts";
import { SqliteStorage } from "../src/db/storage-sqlite.ts";

const wan: WitnessInfo = {
  oobi: "http://localhost:5631/oobi",
  url: "http://localhost:5631",
  aid: "BJi2Gy-mghF6uHwdq_9ZJvpmYm05xvWRW2hGJvD_yk3S",
};

interface WitnessInfo {
  aid: string;
  url: string;
  oobi: string;
}

let storage: SqliteStorage;
let controller: Controller;
let keystore: KeyManager;

beforeEach(() => {
  storage = new SqliteStorage();
  keystore = new KeyManager({
    encrypter: new PassphraseEncrypter("password"),
    storage,
  });
  controller = new Controller({ storage, keyManager: keystore });

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
});
