import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { encodeEvent } from "./events.ts";

describe("encodeEvent", () => {
  test("Should add a version string field", () => {
    const result = encodeEvent({ d: "", t: "icp" });
    assert.ok(result.v.startsWith("KERI10JSON"));
  });

  test("Should compute a SAID for the d field", () => {
    const result = encodeEvent({ d: "", t: "icp" });
    assert.equal(result.d.length, 44);
    assert.equal(result.d.slice(0, 1), "E");
  });

  test("Should be deterministic", () => {
    const a = encodeEvent({ d: "", t: "icp", i: "abc" });
    const b = encodeEvent({ d: "", t: "icp", i: "abc" });
    assert.equal(a.d, b.d);
  });

  test("Should preserve other fields", () => {
    const result = encodeEvent({ d: "", t: "icp", i: "somevalue" });
    assert.equal(result.t, "icp");
    assert.equal(result.i, "somevalue");
  });

  test("Should throw if a required label is missing", () => {
    assert.throws(() => encodeEvent({ t: "icp" }), /missing label 'd'/i);
  });

  test("Should support custom labels", () => {
    const result = encodeEvent({ d: "", i: "", t: "icp" }, { labels: ["d", "i"] });
    assert.equal(result.d.length, 44);
    assert.equal(result.i, result.d);
  });

  test("Should encode version string with custom protocol", () => {
    const result = encodeEvent({ d: "", t: "vcp" }, { protocol: "ACDC" });
    assert.ok(result.v.startsWith("ACDC10JSON"));
  });
});
