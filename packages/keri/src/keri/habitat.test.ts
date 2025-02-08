import test from "node:test";
import { MemoryEventStore } from "../events/event-store.ts";
import { FileSystemKeyStore } from "../main.ts";
import { Habitat } from "./habitat.ts";
import assert from "node:assert";

const witness1: Witness = {
  oobi: "http://localhost:5641/oobi/BNRSNuPrmgAeoossFZSejufyCaPLRRyEPRKn1wUxVeX9",
  url: "http://localhost:5641",
  aid: "BNRSNuPrmgAeoossFZSejufyCaPLRRyEPRKn1wUxVeX9",
};

const witness2: Witness = {
  oobi: "http://localhost:5642/oobi/BDOx8sbSqohKdpMFauzL4wTmzf2WwntKfsPov63-magB",
  url: "http://localhost:5642",
  aid: "BDOx8sbSqohKdpMFauzL4wTmzf2WwntKfsPov63-magB",
};

const witness3: Witness = {
  oobi: "http://localhost:5643/oobi/BIwSajKA3cS5ImCuCYw0cYx271iOiyNPulwY8wfG5wNc",
  url: "http://localhost:5643",
  aid: "BIwSajKA3cS5ImCuCYw0cYx271iOiyNPulwY8wfG5wNc",
};

interface Witness {
  aid: string;
  url: string;
  oobi: string;
}

test("Create identifier", async () => {
  const db = new MemoryEventStore();

  const keystore = new FileSystemKeyStore({ dir: ".keri", passphrase: "abc" });
  const hab = new Habitat({ db, keystore });

  const event = await hab.create({ wits: [] });

  const events = await hab.list(event.i);
  assert.equal(events.length, 1);
  assert.deepStrictEqual(events[0]?.event, event);
});

test.only("Create identifier with single witness", async () => {
  const db = new MemoryEventStore();

  const keystore = new FileSystemKeyStore({ dir: ".keri", passphrase: "abc" });
  const hab = new Habitat({ db, keystore });

  await hab.resolve(witness1.oobi);
  const event = await hab.create({ wits: [witness1.aid] });

  const events = await hab.list(event.i);
  assert.equal(events.length, 1);
  assert.deepStrictEqual(events[0]?.event, event);

  // const response = await fetch(`${witness1.url}/oobi/${event.i}`);
  // assert.equal(response.status, 200);

  // assert.equal(events[0].attachments.length, 3);
});

test("Create identifier with two witnesses", async () => {
  const db = new MemoryEventStore();

  const keystore = new FileSystemKeyStore({ dir: ".keri", passphrase: "abc" });
  const hab = new Habitat({ db, keystore });

  await hab.resolve(witness1.oobi);
  await hab.resolve(witness2.oobi);
  const event = await hab.create({ wits: [witness1.aid, witness2.aid] });

  const events = await hab.list(event.i);
  assert.equal(events.length, 1);
  assert.deepStrictEqual(events[0]?.event, event);

  assert.equal(events[0].attachments.length, 4);

  const response = await fetch(`${witness1.url}/oobi/${event.i}`);
  assert.equal(response.status, 200);
});

test.skip("Create identifier with three witnesses", async () => {
  const db = new MemoryEventStore();

  const keystore = new FileSystemKeyStore({ dir: ".keri", passphrase: "abc" });
  const hab = new Habitat({ db, keystore });

  await hab.resolve(witness1.oobi);
  await hab.resolve(witness2.oobi);
  await hab.resolve(witness3.oobi);
  const event = await hab.create({ wits: [witness1.aid, witness2.aid, witness3.aid] });

  const events = await hab.list(event.i);
  assert.equal(events.length, 1);
  assert.deepStrictEqual(events[0]?.event, event);

  assert.equal(events[0].attachments.length, 5);

  const response = await fetch(`${witness1.url}/oobi/${event.i}`);
  assert.strictEqual(response.status, 200);
});
