import assert from "node:assert";
import { keri } from "#keri/main.ts";
import { createController, resolveWitness } from "./utils.ts";

const wan = await resolveWitness("http://localhost:5642");
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
