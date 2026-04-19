import { keri } from "#keri/core";
import assert from "node:assert";
import test, { after, before } from "node:test";
import { KERIPy } from "./keripy.ts";
import { createController, type Endpoint, startKerijsMailbox, startKeripyWitness } from "./utils.ts";

let witness: Endpoint;
let mailbox: Endpoint;
const abortController = new AbortController();

before(async () => {
  // TODO: replace the KERIpy witness with a kerijs witness once supported
  [witness, mailbox] = await Promise.all([
    startKeripyWitness({ signal: abortController.signal }),
    startKerijsMailbox({ signal: abortController.signal }),
  ]);
});

after(() => {
  abortController.abort();
});

test("forward exchange through mailbox", async () => {
  const alice = createController();
  const bob = createController();

  await alice.introduce(witness.oobi);
  await bob.introduce(witness.oobi);

  const aliceState = await alice.incept({ wits: [witness.aid], toad: 1 });
  const bobState = await bob.incept({ wits: [witness.aid], toad: 1 });

  await alice.introduce(mailbox.oobi);
  await alice.reply({
    id: aliceState.id,
    route: "/end/role/add",
    record: { cid: aliceState.id, eid: mailbox.aid, role: "mailbox" },
  });

  await bob.introduce(mailbox.oobi);
  await bob.introduce(`${witness.url}/oobi/${aliceState.id}/mailbox`);
  await alice.introduce(`${witness.url}/oobi/${bobState.id}/mailbox`);

  const words = ["bob", "to", "alice"];

  await bob.forward({
    message: keri.exchange({
      sender: bobState.id,
      route: "/challenge/response",
      query: {},
      anchor: { i: bobState.id, words },
      embeds: {},
    }),
    recipient: aliceState.id,
    sender: bobState.id,
    topic: "challenge",
  });

  const inbox = await alice.query(aliceState.id, "challenge");
  assert.equal(inbox.length, 1);
  assert.equal(inbox[0].body.t, "exn");
  assert.deepEqual(inbox[0].body.a, { i: bobState.id, words });
});

test("KERIpy controller receives forwarded exchange via KERIjs mailbox", async () => {
  const alice = new KERIPy();
  await alice.init();
  await alice.oobi.resolve(witness.oobi, "wit");
  await alice.incept({ wits: [witness.aid], toad: 1 });

  await alice.oobi.resolve(mailbox.oobi, "mbx");
  await alice.ends.add({ eid: mailbox.aid });

  const aliceAid = await alice.aid();

  const bob = createController();
  await bob.introduce(witness.oobi);
  await bob.introduce(mailbox.oobi);

  const bobState = await bob.incept({ wits: [witness.aid], toad: 1 });

  await bob.reply({
    id: bobState.id,
    route: "/end/role/add",
    record: { cid: bobState.id, eid: mailbox.aid, role: "mailbox" },
  });

  await bob.introduce(`${witness.url}/oobi/${aliceAid}/mailbox`);
  await alice.oobi.resolve(`${witness.url}/oobi/${bobState.id}/mailbox`, "bob");

  const words = await alice.challenge.generate();

  await bob.forward({
    message: keri.exchange({
      sender: bobState.id,
      route: "/challenge/response",
      query: {},
      anchor: { i: bobState.id, words },
      embeds: {},
    }),
    recipient: aliceAid,
    sender: bobState.id,
    topic: "challenge",
  });

  await alice.challenge.verify({ words, signer: "bob" });
});
