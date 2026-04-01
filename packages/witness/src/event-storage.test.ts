import assert from "node:assert";
import test, { before, beforeEach, describe } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Matter } from "cesr";
import { type InceptEvent, type KeyEvent, keri } from "keri";
import { createTable } from "./dynamo-client.ts";
import { EventStorage } from "./event-storage.ts";
import { createSeed } from "./seed.ts";

let icp: KeyEvent<InceptEvent>;

describe("Event storage", () => {
  let storage: EventStorage;

  before(async () => {
    const pubKey0 = new Matter({
      code: Matter.Code.Ed25519,
      raw: ed25519.getPublicKey(createSeed("0", "salt")),
    }).text();
    const pubKey1 = new Matter({
      code: Matter.Code.Ed25519,
      raw: ed25519.getPublicKey(createSeed("1", "salt")),
    }).text();

    icp = keri.incept({
      signingKeys: [pubKey0],
      nextKeys: [pubKey1],
    });
  });

  beforeEach(async () => {
    const tableName = `test_events_${crypto.randomUUID()}`;
    const endpoint = "http://admin:password@localhost:8000";
    const client = await createTable(tableName, endpoint);
    storage = new EventStorage({
      tableName,
      client,
    });
  });

  test("Should save event", async () => {
    await storage.saveEvent({
      message: icp,
      timestamp: new Date(),
    });
  });

  test("Should retrieve events by AID", async () => {
    await storage.saveEvent({
      message: icp,
      timestamp: new Date(),
    });

    const result = await storage.listEvents({
      i: icp.body.i,
    });

    assert.strictEqual(result.length, 1);
  });
});
