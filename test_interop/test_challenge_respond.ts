import assert from "node:assert";
import test, { after, before } from "node:test";
import { keri } from "#keri/core";
import { KERIPy } from "./keripy.ts";
import { createController, type Endpoint, startKeripyWitness } from "./utils.ts";

let wan: Endpoint;
let wil: Endpoint;
const abortController = new AbortController();

before(async () => {
  [wan, wil] = await Promise.all([
    startKeripyWitness({ signal: abortController.signal }),
    startKeripyWitness({ signal: abortController.signal }),
  ]);
});

after(() => {
  abortController.abort();
});

test("KERIpy challenge-response with KERIjs signer", async () => {
  const keripy = new KERIPy();

  // Set up KERIpy identity
  await keripy.init();
  await keripy.oobi.resolve(wan.oobi, "wan");
  await keripy.oobi.resolve(wil.oobi, "wil");
  await keripy.incept({ wits: [wan.aid, wil.aid], toad: 1 });
  await keripy.ends.add({ eid: wan.aid });

  const keripy_aid = await keripy.aid();

  // Set up KeriJS identity
  const controller = createController();
  await controller.introduce(wan.oobi);
  await controller.introduce(wil.oobi);

  const jsState = await controller.incept({ wits: [wan.aid], toad: 1 });

  // Cross-resolve OOBIs
  const kerijs_oobi = `${wan.url}/oobi/${jsState.id}`;
  const keripy_oobi = `${wan.url}/oobi/${keripy_aid}`;

  await controller.introduce(keripy_oobi);
  await keripy.oobi.resolve(kerijs_oobi, "kerijs");

  // KERIpy generates challenge words; KeriJS sends them back
  const words = await keripy.challenge.generate();
  assert.equal(words.length, 12);

  const exn = keri.exchange({
    sender: jsState.id,
    route: "/challenge/response",
    anchor: { i: jsState.id, words },
  });

  await controller.forward({
    message: exn,
    recipient: keripy_aid,
    sender: jsState.id,
    topic: "challenge",
  });

  // KERIpy verifies — exits 0 on success, throws on failure
  await keripy.challenge.verify({ words, signer: "kerijs" });
});

test("KeriJS challenge-response between two controllers", async () => {
  const controller0 = createController();
  const controller1 = createController();

  await controller0.introduce(wan.oobi);
  await controller1.introduce(wan.oobi);
  const state0 = await controller0.incept({
    wits: [wan.aid],
    toad: 1,
  });
  const state1 = await controller1.incept({
    wits: [wan.aid],
    toad: 1,
  });

  await controller0.reply({
    id: state0.id,
    route: "/end/role/add",
    record: {
      cid: state0.id,
      eid: wan.aid,
      role: "mailbox",
    },
  });

  await controller1.reply({
    id: state1.id,
    route: "/end/role/add",
    record: {
      cid: state1.id,
      eid: wan.aid,
      role: "mailbox",
    },
  });

  await controller1.introduce(`${wan.url}/oobi/${state0.id}/mailbox`);
  await controller0.introduce(`${wan.url}/oobi/${state1.id}/mailbox`);

  const words = ["test", "challenge"];

  await controller1.forward({
    message: keri.exchange({
      sender: state1.id,
      route: "/challenge/response",
      query: {},
      anchor: { i: state1.id, words },
      embeds: {},
    }),
    recipient: state0.id,
    sender: state1.id,
    topic: "challenge",
  });

  const result = await controller0.query(state0.id, "challenge");

  assert.equal(result.length, 1);
  assert.equal(result[0].body.t, "exn");
  assert.deepEqual(result[0].body.a, {
    i: state1.id,
    words,
  });
});
