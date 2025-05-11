import { beforeEach, describe, test } from "node:test";
import assert from "node:assert";
import { keri } from "../events/events.ts";
import { ControllerEventStore } from "./event-store.ts";
import { cesr, encodeIndexedSignature, encodeSignature, MatterCode } from "cesr/__unstable__";
import { randomBytes } from "node:crypto";
import { SqliteStorage } from "../db/storage-sqlite.ts";

let db: SqliteStorage;
let store: ControllerEventStore;

function randomKey() {
  return cesr.encodeMatter({ code: MatterCode.Ed25519, raw: randomBytes(32) });
}

function increment(s: string): string {
  return (parseInt(s, 16) + 1).toString(16);
}

beforeEach(() => {
  db = new SqliteStorage();
  db.init();
  store = new ControllerEventStore(db);
});

describe("Key value store", () => {
  test("Should list inserted event", async () => {
    const event0 = keri.incept({ k: [randomKey()] });

    await store.save({ event: event0 });
    const result = await store.list(event0.i);

    assert.equal(result.length, 1);
    assert.partialDeepStrictEqual(result[0], {
      event: event0,
    });
  });

  test("Should list events for identifier", async () => {
    const event00 = keri.incept({ k: [randomKey()] });
    const event01 = keri.interact({ p: event00.d, i: event00.i, s: increment(event00.s) });

    const event10 = keri.incept({ k: [randomKey()] });
    const event11 = keri.interact({ p: event10.d, i: event10.i, s: increment(event10.s) });

    await store.save({ event: event00 });
    await store.save({ event: event10 });
    await store.save({ event: event01 });
    await store.save({ event: event11 });

    const result0 = await store.list(event00.i);
    assert.equal(result0.length, 2);
    assert.partialDeepStrictEqual(result0[0], {
      event: event00,
    });

    assert.partialDeepStrictEqual(result0[1], {
      event: event01,
    });

    const result1 = await store.list(event10.i);
    assert.equal(result1.length, 2);
    assert.partialDeepStrictEqual(result1[0], {
      event: event10,
    });

    assert.partialDeepStrictEqual(result1[1], {
      event: event11,
    });
  });

  test("Should return state for identifier", async () => {
    const event0 = keri.incept({ k: [randomKey()] });
    const event1 = keri.interact({ p: event0.d, i: event0.i, s: increment(event0.s) });

    await store.save({ event: event0 });
    await store.save({ event: event1 });

    const result0 = await store.state(event0.i);
    assert.equal(result0.s, "1");
    assert.equal(result0.i, event0.i);
    assert.partialDeepStrictEqual(result0, {
      i: event1.i,
      p: event0.d,
      d: event1.d,
      s: event1.s,
      et: "ixn",
      ee: {
        s: event0.s,
        d: event0.d,
        br: [],
        ba: event0.b,
      },
    });
  });

  test("Should return signature for event", async () => {
    const event = keri.incept({ k: [randomKey(), randomKey(), randomKey()] });
    const signature0 = encodeIndexedSignature("ed25519", randomBytes(64), 0);
    const signature1 = encodeIndexedSignature("ed25519", randomBytes(64), 2);

    await store.save({
      event,
      signatures: [signature0, signature1],
    });

    const events = await store.list(event.i);

    assert.equal(events.length, 1);
    assert.equal(events[0].signatures.length, 2);
    assert.equal(events[0].signatures[0], signature0);
    assert.equal(events[0].signatures[1], signature1);
  });

  test("Should return receipts for event", async () => {
    const event = keri.incept({ k: [randomKey(), randomKey(), randomKey()] });
    const signature0 = encodeSignature("ed25519", randomBytes(64));
    const signature1 = encodeSignature("ed25519", randomBytes(64));

    await store.save({ event });

    await store.save({
      event: keri.receipt({
        d: event.d,
        i: event.i,
        s: event.s,
      }),
      receipts: [
        {
          backer: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
          signature: signature0,
        },
        {
          backer: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
          signature: signature1,
        },
      ],
    });

    const events = await store.list(event.i);

    assert.equal(events.length, 1);
    assert.equal(events[0].receipts.length, 2);
    assert.deepEqual(events[0].receipts[0], {
      backer: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
      signature: signature0,
    });
    assert.deepEqual(events[0].receipts[1], {
      backer: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
      signature: signature1,
    });
  });

  test("Can insert and read seal", async () => {
    const event = keri.incept({ k: [randomKey()] });

    const seal = {
      i: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
      d: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
      s: "3",
    };

    await store.save({
      event,
      seal,
    });

    const events = await store.list(event.i);

    assert.equal(events.length, 1);
    assert.deepEqual(events[0].event, event);
    assert.deepEqual(events[0].seal, seal);
  });

  test("Should return end role for identifier", async () => {
    const cid = "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM";
    const event = keri.reply({
      r: "/end/role/add",
      a: {
        eid: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
        role: "mailbox",
        cid: cid,
      },
    });

    await store.save({ event });

    const endrole = await store.endrole(cid, "mailbox");

    assert.deepStrictEqual(endrole, {
      cid: "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
      eid: "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2",
      role: "mailbox",
    });
  });

  test("Should return location for identifier", async () => {
    const eid = "BHJ73vhhuZBd4U-QtQ7FuYrlQx6cF_Fxpv-OSEqghRo2";

    const event = keri.reply({
      r: "/loc/scheme",
      a: {
        scheme: "http",
        url: "http://localhost:5642",
        eid: eid,
      },
    });

    await store.save({ event });

    const location = await store.location(eid);

    assert.deepStrictEqual(location, {
      scheme: "http",
      url: "http://localhost:5642",
      eid: eid,
    });
  });
});
