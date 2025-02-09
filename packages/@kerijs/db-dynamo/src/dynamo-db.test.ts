import { before, test } from "node:test";
import assert from "node:assert";
import { DynamoEventStore } from "./dynamo-db.ts";
import { cesr, keri, CounterCode, MatterCode } from "keri";
import { randomBytes } from "@noble/hashes/utils";
import { randomUUID } from "node:crypto";

let db: DynamoEventStore;

before(async () => {
  db = new DynamoEventStore({
    endpoint: "http://localhost:8000",
    region: "no-region",
    tableName: `test_${randomUUID()}`,
    credentials: {
      secretAccessKey: "password",
      accessKeyId: "admin",
    },
  });

  await db.init();
});

test("Should insert and read event", async () => {
  const event = keri.incept({ k: [], kt: [], n: [], nt: [] });

  await db.saveEvent(event);
  const events = await db.list({ i: event.i });

  assert.equal(events.length, 1);
  assert.deepEqual(events[0].event, event);
});

test("Can insert and read attachment", async () => {
  const event = keri.incept({ k: [], kt: [], n: [], nt: [] });

  const signature = cesr.index(cesr.encode(MatterCode.Ed25519_Sig, randomBytes(64)), 1);
  await db.saveEvent(event);
  await db.saveAttachment(event.d, {
    code: CounterCode.ControllerIdxSigs,
    value: signature,
  });

  const events = await db.list({ i: event.i });

  assert.equal(events.length, 1);
  assert.deepEqual(events[0].event, event);
  assert.deepEqual(events[0].attachments, [{ code: CounterCode.ControllerIdxSigs, value: signature }]);
});

test("Should query for event type", async () => {
  const event = keri.reply({
    dt: "2022-01-20T12:57:59.823350+00:00",
    r: "/loc/scheme",
    a: {
      eid: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
      scheme: "http",
      url: "http://127.0.0.1:5631/",
    },
  });

  await db.saveEvent(event);
  const locations = await db.list({ t: "rpy", r: "/loc/scheme" });

  assert.deepStrictEqual(locations[0].event, event);
});
