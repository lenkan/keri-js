import { describe, test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { keri, type KeyState, type KeyEvent, type InceptEvent, Message } from "#keri/core";
import { SqliteControllerStorage, NodeSqliteDatabase } from "#keri/sqlite-storage";

function incept(): KeyEvent<InceptEvent> {
  const key0 = keri.utils.generateKeyPair();
  const key1 = keri.utils.generateKeyPair();
  return keri.incept({ signingKeys: [key0.publicKey], nextKeys: [key1.publicKeyDigest] });
}

describe("SqliteControllerStorage", () => {
  let db: DatabaseSync;
  let storage: SqliteControllerStorage;

  beforeEach(() => {
    db = new DatabaseSync(":memory:");
    storage = new SqliteControllerStorage(new NodeSqliteDatabase(db));
  });

  afterEach(() => {
    db.close();
  });

  describe("iterate key events", () => {
    test("returns events ordered by sn", () => {
      const icp = incept();

      // Build a minimal state from each event to derive the next, without signature validation
      const state0: KeyState = {
        identifier: icp.body.i,
        signingThreshold: "1",
        signingKeys: [],
        nextThreshold: "0",
        nextKeyDigests: [],
        backerThreshold: "0",
        backers: [],
        configTraits: [],
        lastEvent: { i: icp.body.i, s: icp.body.s, d: icp.body.d },
        lastEstablishment: { i: icp.body.i, s: icp.body.s, d: icp.body.d },
      };
      const ixn1 = keri.interact(state0);
      const state1: KeyState = { ...state0, lastEvent: { i: icp.body.i, s: ixn1.body.s, d: ixn1.body.d } };
      const ixn2 = keri.interact(state1);

      storage.saveMessage(icp);
      storage.saveMessage(ixn2); // save out of order
      storage.saveMessage(ixn1);

      const events = [...storage.getKeyEvents(icp.body.i)];

      assert.equal(events.length, 3);
      assert.equal(events[0].body.t, "icp");
      assert.equal(events[1].body.t, "ixn");
      assert.equal(events[2].body.t, "ixn");
      assert.equal((events[0].body as { s: string }).s, "0");
      assert.equal((events[1].body as { s: string }).s, "1");
      assert.equal((events[2].body as { s: string }).s, "2");
    });

    test("returns empty array when prefix not found", () => {
      const events = [...storage.getKeyEvents("UNKNOWN")];
      assert.equal(events.length, 0);
    });

    test("ignores duplicate event ids on save", () => {
      const icp = incept();

      storage.saveMessage(icp);
      storage.saveMessage(icp);

      const events = [...storage.getKeyEvents(icp.body.i)];
      assert.equal(events.length, 1);
    });

    test("preserves SealSourceCouples attachments round-trip", () => {
      const icp = incept();
      const seal = { digest: icp.body.d, snu: icp.body.s };
      const vcp = keri.registry({ ii: icp.body.i });
      const message = new Message(vcp.body, { SealSourceCouples: [seal] });

      storage.saveMessage(message);

      const result = storage.getRegistry(vcp.body.i);
      assert(result);
      assert.deepStrictEqual(result.attachments.SealSourceCouples, [seal]);
    });

    test("preserves SealSourceTriples attachments round-trip", () => {
      const icp = incept();
      const triple = { prefix: icp.body.i, snu: icp.body.s, digest: icp.body.d };
      const vcp = keri.registry({ ii: icp.body.i });
      const message = new Message(vcp.body, { SealSourceTriples: [triple] });

      storage.saveMessage(message);

      const [result] = [...storage.getRegistriesByOwner(icp.body.i)];
      assert.deepStrictEqual(result.attachments.SealSourceTriples, [triple]);
    });
  });

  describe("iterate reply events", () => {
    test("filters by types", () => {
      const icp = incept();
      const rpy = keri.reply({ r: "/loc/scheme", a: { url: "http://localhost" } });

      storage.saveMessage(icp);
      storage.saveMessage(rpy);

      const rpyEvents = [...storage.getReplies()];
      assert.equal(rpyEvents.length, 1);
      assert.equal(rpyEvents[0].body.t, "rpy");
    });

    test("filters by route", () => {
      storage.saveMessage(keri.reply({ r: "/loc/scheme", a: {} }));
      storage.saveMessage(keri.reply({ r: "/end/role/add", a: {} }));

      const events = [...storage.getReplies({ route: "/loc/scheme" })];
      assert.equal(events.length, 1);
      assert.equal((events[0].body as { r: string }).r, "/loc/scheme");
    });

    test("filters by eid", () => {
      storage.saveMessage(keri.reply({ r: "/loc/scheme", a: { eid: "EID_A", url: "http://a" } }));
      storage.saveMessage(keri.reply({ r: "/loc/scheme", a: { eid: "EID_B", url: "http://b" } }));

      const events = [...storage.getReplies({ eid: "EID_A" })];
      assert.equal(events.length, 1);
      assert.equal(events[0].body.a.eid, "EID_A");
    });

    test("filters by cid", () => {
      storage.saveMessage(keri.reply({ r: "/end/role/add", a: { cid: "CID_1", role: "controller", eid: "EID_A" } }));
      storage.saveMessage(keri.reply({ r: "/end/role/add", a: { cid: "CID_2", role: "controller", eid: "EID_B" } }));

      const events = [...storage.getReplies({ cid: "CID_1" })];
      assert.equal(events.length, 1);
      assert.equal(events[0].body.a.cid, "CID_1");
    });
  });

  describe("getRegistry", () => {
    test("returns null when registry not found", () => {
      assert.equal(storage.getRegistry("UNKNOWN"), null);
    });

    test("returns registry event body when found", () => {
      const icp = incept();
      const vcp = keri.registry({ ii: icp.body.i });

      storage.saveMessage(vcp);

      const result = storage.getRegistry(vcp.body.i as string);
      assert.ok(result);
      assert.equal(result.body.d, vcp.body.d);
      assert.equal(result.body.ii, icp.body.i);
    });

    test("returns null for non-vcp event with matching prefix", () => {
      const icp = incept();
      storage.saveMessage(icp);

      assert.equal(storage.getRegistry(icp.body.i), null);
    });
  });

  describe("getRegistriesByOwner", () => {
    test("returns registries for the given owner", () => {
      const owner = incept();
      const reg1 = keri.registry({ ii: owner.body.i });
      const reg2 = keri.registry({ ii: owner.body.i });

      storage.saveMessage(new Message(reg1.body));
      storage.saveMessage(new Message(reg2.body));

      const registries = [...storage.getRegistriesByOwner(owner.body.i)];
      assert.equal(registries.length, 2);
      assert.equal(registries[0].body.d, reg1.body.d);
      assert.equal(registries[1].body.d, reg2.body.d);
    });

    test("excludes registries belonging to other owners", () => {
      const owner1 = incept();
      const owner2 = incept();

      storage.saveMessage(keri.registry({ ii: owner1.body.i }));
      storage.saveMessage(keri.registry({ ii: owner2.body.i }));

      const registries = [...storage.getRegistriesByOwner(owner1.body.i)];
      assert.equal(registries.length, 1);
      assert.equal(registries[0].body.ii, owner1.body.i);
    });

    test("returns empty array when owner has no registries", () => {
      assert.equal([...storage.getRegistriesByOwner("UNKNOWN")].length, 0);
    });
  });

  describe("getCredentialEvents", () => {
    test("should save and list credential status events", () => {
      const icp = incept();
      storage.saveMessage(icp);

      const credential = keri.credential({
        i: icp.body.i,
        ri: "ERegistry",
        s: "ESchema",
        a: { i: "EHolder" },
        r: { usageDisclaimer: { l: "Disclaimer" } },
      });

      const issuanceEvent = keri.issue({
        i: credential.body.d,
        ri: credential.body.ri,
      });
      issuanceEvent.attachments.SealSourceCouples.push({ digest: icp.body.d, snu: icp.body.s });

      storage.saveMessage(issuanceEvent);

      const revEvent = keri.revoke({
        i: credential.body.d,
        ri: credential.body.ri,
        p: issuanceEvent.body.d,
        dt: issuanceEvent.body.dt,
      });

      storage.saveMessage(revEvent);

      const events = [...storage.getCredentialEvents(credential.body.d)];

      assert.equal(events.length, 2);
      assert.equal(events[0].body.t, "iss");
      assert.equal(events[1].body.t, "rev");
      assert.deepStrictEqual(events[0].attachments.SealSourceCouples, [
        {
          digest: icp.body.d,
          snu: icp.body.s,
        },
      ]);
    });
  });

  describe("credentials", () => {
    test("should save and get credential", () => {
      const credential = keri.credential({
        i: "EIssuer",
        ri: "ERegistry",
        s: "ESchema",
        a: { i: "EHolder" },
        r: { usageDisclaimer: { l: "Usage disclaimer" } },
      });

      storage.saveMessage(credential);

      const result = storage.getCredential(credential.body.d);
      assert.deepStrictEqual(result, credential.body);
    });

    test("should list credentials by registry", () => {
      const credentialA = keri.credential({
        i: "EIssuer",
        ri: "ERegistryA",
        s: "ESchema",
        a: { i: "EHolderA" },
        r: { usageDisclaimer: { l: "A" } },
      });

      const credentialB = keri.credential({
        i: "EIssuer",
        ri: "ERegistryA",
        s: "ESchema",
        a: { i: "EHolderB" },
        r: { usageDisclaimer: { l: "B" } },
      });

      const credentialC = keri.credential({
        i: "EIssuer",
        ri: "ERegistryB",
        s: "ESchema",
        a: { i: "EHolderC" },
        r: { usageDisclaimer: { l: "C" } },
      });

      storage.saveMessage(credentialA);
      storage.saveMessage(credentialC);
      storage.saveMessage(credentialB);

      const result = storage.getCredentialsByRegistry("ERegistryA");

      assert.equal(result.length, 2);
      assert.equal(result[0].ri, "ERegistryA");
      assert.equal(result[1].ri, "ERegistryA");
      assert.equal(result[0].d, credentialA.body.d);
      assert.equal(result[1].d, credentialB.body.d);
    });

    test("returns null when credential not found", () => {
      assert.equal(storage.getCredential("UNKNOWN"), null);
    });
  });

  describe("key storage", () => {
    test("saves and retrieves encrypted private key", () => {
      storage.saveKey("PUBKEY", "DIGEST", "ENCRYPTED");
      assert.equal(storage.getKey("PUBKEY"), "ENCRYPTED");
    });

    test("retrieves public key by digest", () => {
      storage.saveKey("PUBKEY", "DIGEST", "ENCRYPTED");
      assert.equal(storage.getPublicKeyByDigest("DIGEST"), "PUBKEY");
    });

    test("throws when key not found", () => {
      assert.throws(() => storage.getKey("UNKNOWN"), /Key not found/);
    });

    test("throws when digest not found", () => {
      assert.throws(() => storage.getPublicKeyByDigest("UNKNOWN"), /Key not found/);
    });

    test("ignores duplicate saveKey calls", () => {
      storage.saveKey("PUBKEY", "DIGEST", "ENCRYPTED1");
      storage.saveKey("PUBKEY", "DIGEST", "ENCRYPTED2");
      assert.equal(storage.getKey("PUBKEY"), "ENCRYPTED1");
    });
  });
});
