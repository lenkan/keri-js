import test from "node:test";
import { MemoryEventStore } from "../events/event-store.ts";
import { FileSystemKeyStore, incept } from "../main.ts";
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

// const witness3: Witness = {
//   oobi: "http://localhost:5643/oobi/BIwSajKA3cS5ImCuCYw0cYx271iOiyNPulwY8wfG5wNc",
//   url: "http://localhost:5643",
//   aid: "BIwSajKA3cS5ImCuCYw0cYx271iOiyNPulwY8wfG5wNc",
// };

interface Witness {
  aid: string;
  url: string;
  oobi: string;
}

test("Create identifier", async () => {
  const db = new MemoryEventStore();

  const keystore = new FileSystemKeyStore({ dir: ".keri", passphrase: "abc" });
  const hab = new Habitat({ db, keystore });
  const key = await keystore.incept();
  const event = incept({
    b: [],
    k: [key.current],
    n: [key.next],
  });

  const raw = new TextEncoder().encode(JSON.stringify(event));
  const sigs = await Promise.all(event.k.map((key) => keystore.sign(key, raw)));

  await hab.create(event, sigs);

  const events = await hab.list(event.i);
  assert.equal(events.length, 1);
  assert.deepStrictEqual(events[0]?.event, event);
});

test("Create identifier with single witness", async () => {
  const db = new MemoryEventStore();

  const keystore = new FileSystemKeyStore({ dir: ".keri", passphrase: "abc" });
  const hab = new Habitat({ db, keystore });
  const key = await keystore.incept();

  await hab.resolve(witness1.oobi);

  const event = incept({
    b: [witness1.aid],
    k: [key.current],
    n: [key.next],
  });

  const raw = new TextEncoder().encode(JSON.stringify(event));
  const sigs = await Promise.all(event.k.map((key) => keystore.sign(key, raw)));

  await hab.create(event, sigs);

  const events = await hab.list(event.i);
  assert.equal(events.length, 1);
  assert.deepStrictEqual(events[0]?.event, event);
});

test.skip("Create identifier with two witnesses", async () => {
  const db = new MemoryEventStore();

  const keystore = new FileSystemKeyStore({ dir: ".keri", passphrase: "abc" });
  const hab = new Habitat({ db, keystore });
  const key0 = await keystore.incept();
  const key1 = await keystore.incept();

  await hab.resolve(witness1.oobi);
  await hab.resolve(witness2.oobi);

  const event = incept({
    b: [witness1.aid, witness2.aid],
    k: [key0.current, key1.current],
    n: [key0.next, key1.current],
  });

  const raw = new TextEncoder().encode(JSON.stringify(event));
  const sigs = await Promise.all(event.k.map((key) => keystore.sign(key, raw)));

  await hab.create(event, sigs);

  const events = await hab.list(event.i);
  assert.equal(events.length, 1);
  assert.deepStrictEqual(events[0]?.event, event);

  assert.equal(events[0].attachments.length, 4);

  const response = await fetch(`${witness1.url}/oobi/${event.i}`);
  assert.equal(response.status, 200);
});
