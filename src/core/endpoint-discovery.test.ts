import assert from "node:assert/strict";
import { basename } from "node:path";
import test, { describe } from "node:test";
import { resolveEndRole, resolveLocation } from "./endpoint-discovery.ts";
import { incept } from "./key-event.ts";
import { generateKeyPair } from "./keys.ts";
import { reply } from "./routed-event.ts";

function createAid() {
  const key = generateKeyPair();
  const next = generateKeyPair();
  return incept({ signingKeys: [key.publicKey], nextKeys: [next.publicKeyDigest] }).body.i;
}

describe(basename(import.meta.url), () => {
  describe("resolveEndRole", () => {
    test("should return matching record", () => {
      const cid = createAid();
      const eid = createAid();
      const replies = [reply({ r: "/end/role/add", a: { cid, role: "agent", eid } })];
      const result = resolveEndRole(replies, cid, "agent");
      assert.deepEqual(result, { cid, role: "agent", eid });
    });

    test("should return null when no replies", () => {
      assert.equal(resolveEndRole([], createAid(), "agent"), null);
    });

    test("should return null when cid does not match", () => {
      const eid = createAid();
      const replies = [reply({ r: "/end/role/add", a: { cid: createAid(), role: "agent", eid } })];
      assert.equal(resolveEndRole(replies, createAid(), "agent"), null);
    });

    test("should return null when role does not match", () => {
      const cid = createAid();
      const eid = createAid();
      const replies = [reply({ r: "/end/role/add", a: { cid, role: "mailbox", eid } })];
      assert.equal(resolveEndRole(replies, cid, "agent"), null);
    });

    test("should return last matching record when multiple match", () => {
      const cid = createAid();
      const eid1 = createAid();
      const eid2 = createAid();
      const replies = [
        reply({ r: "/end/role/add", a: { cid, role: "agent", eid: eid1 } }),
        reply({ r: "/end/role/add", a: { cid, role: "agent", eid: eid2 } }),
      ];
      assert.equal(resolveEndRole(replies, cid, "agent")?.eid, eid2);
    });

    test("should skip non-endrole replies", () => {
      const cid = createAid();
      const eid = createAid();
      const replies = [
        reply({ r: "/loc/scheme", a: { eid, scheme: "http", url: "http://localhost" } }),
        reply({ r: "/end/role/add", a: { cid, role: "agent", eid } }),
      ];
      assert.equal(resolveEndRole(replies, cid, "agent")?.eid, eid);
    });
  });

  describe("resolveLocation", () => {
    test("should return matching http location", () => {
      const eid = createAid();
      const replies = [reply({ r: "/loc/scheme", a: { eid, scheme: "http", url: "http://localhost:5642" } })];
      assert.deepEqual(resolveLocation(replies, eid), { eid, scheme: "http", url: "http://localhost:5642" });
    });

    test("should return matching https location", () => {
      const eid = createAid();
      const replies = [reply({ r: "/loc/scheme", a: { eid, scheme: "https", url: "https://example.com" } })];
      assert.equal(resolveLocation(replies, eid)?.scheme, "https");
    });

    test("should return null when no replies", () => {
      assert.equal(resolveLocation([], createAid()), null);
    });

    test("should return null when eid does not match", () => {
      const replies = [
        reply({ r: "/loc/scheme", a: { eid: createAid(), scheme: "http", url: "http://localhost:5642" } }),
      ];
      assert.equal(resolveLocation(replies, createAid()), null);
    });

    test("should skip non-http/https schemes", () => {
      const eid = createAid();
      const replies = [reply({ r: "/loc/scheme", a: { eid, scheme: "tcp", url: "tcp://localhost:5642" } })];
      assert.equal(resolveLocation(replies, eid), null);
    });

    test("should skip non-location replies", () => {
      const eid = createAid();
      const cid = createAid();
      const replies = [
        reply({ r: "/end/role/add", a: { cid, role: "agent", eid } }),
        reply({ r: "/loc/scheme", a: { eid, scheme: "http", url: "http://localhost:5642" } }),
      ];
      assert.equal(resolveLocation(replies, eid)?.url, "http://localhost:5642");
    });
  });
});
