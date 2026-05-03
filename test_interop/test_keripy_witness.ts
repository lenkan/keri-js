import assert from "node:assert";
import test, { after, before } from "node:test";
import { parse } from "#keri/cesr";
import { KERIPy } from "./keripy.ts";
import {
  collectAsync,
  createController,
  type Endpoint,
  type KeripyWitness,
  startKerijsMailbox,
  startKeripyWitness,
} from "./utils.ts";

let wan: KeripyWitness;
let wes: KeripyWitness;
let mailbox: Endpoint;
const abortController = new AbortController();

before(async () => {
  [wan, wes, mailbox] = await Promise.all([
    startKeripyWitness({ signal: abortController.signal }),
    startKeripyWitness({ signal: abortController.signal }),
    startKerijsMailbox({ signal: abortController.signal }),
  ]);
});

after(() => {
  abortController.abort();
});

test("Create identifier with single witness", async () => {
  const keripy = new KERIPy();
  await keripy.init();
  await keripy.oobi.resolve(wan.oobi, "wan");

  await wan.kli.oobi.resolve(wes.oobi, "wes");
  await keripy.oobi.resolve(wes.oobi, "wes");

  await keripy.incept({ wits: [wan.aid], toad: 1, receiptEndpoint: true });
  const aid = await keripy.aid();

  await keripy.ends.add({ eid: wes.aid, role: "mailbox" });

  const response = await fetch(`${wan.url}/oobi/${aid}/mailbox`);
  assert.equal(response.status, 200);
  assert(response.body, "Expected response body");

  const parsed = await collectAsync(parse(response.body));
  assert(parsed.length >= 3, "Expected at least 3 messages in response");
  assert.partialDeepStrictEqual(parsed[0].body, {
    t: "icp",
    d: aid,
    i: aid,
    s: "0",
  });
  assert.partialDeepStrictEqual(parsed[1].body, {
    t: "rpy",
    r: "/loc/scheme",
    a: {
      eid: wes.aid,
      scheme: "http",
      url: wes.url,
    },
  });
  assert.partialDeepStrictEqual(parsed[2].body, {
    t: "rpy",
    r: "/end/role/add",
    a: {
      cid: aid,
      role: "mailbox",
      eid: wes.aid,
    },
  });
});

test("Create kerijs identifier with single witness", async () => {
  const controller = createController();

  await controller.introduce(wan.oobi);
  await controller.introduce(wes.oobi);
  await controller.introduce(mailbox.oobi);

  await wan.kli.oobi.resolve(mailbox.oobi, "wil");

  const state = await controller.incept({ wits: [wan.aid], toad: 1 });
  const aid = state.id;

  await controller.reply({
    id: state.id,
    route: "/end/role/add",
    record: {
      cid: state.id,
      role: "mailbox",
      eid: mailbox.aid,
    },
  });

  const response = await fetch(`${wan.url}/oobi/${state.id}/mailbox`);
  assert.equal(response.status, 200);
  assert(response.body, "Expected response body");

  const parsed = await collectAsync(parse(response.body));
  for (const message of parsed) {
    console.log(message);
  }
  assert(parsed.length >= 3, "Expected at least 3 messages in response");
  assert.partialDeepStrictEqual(parsed[0].body, {
    t: "icp",
    d: aid,
    i: aid,
    s: "0",
  });
  assert.partialDeepStrictEqual(parsed[1].body, {
    t: "rpy",
    r: "/loc/scheme",
    a: {
      eid: mailbox.aid,
      scheme: "http",
      url: mailbox.url,
    },
  });
  assert.partialDeepStrictEqual(parsed[2].body, {
    t: "rpy",
    r: "/end/role/add",
    a: {
      cid: aid,
      role: "mailbox",
      eid: mailbox.aid,
    },
  });
});
