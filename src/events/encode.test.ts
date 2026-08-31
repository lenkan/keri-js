import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeEvent, timestamp } from "./encode.ts";

describe(basename(import.meta.url), () => {
  // KERI writes microseconds and a `Date` holds milliseconds, so a timestamp off the wire has to
  // travel as text. Rounding `…019676` to `…019000` would change the digest of the event carrying it.
  test("should keep a timestamp given as a string", () => {
    assert.equal(timestamp("2025-04-17T21:53:17.019676+00:00"), "2025-04-17T21:53:17.019676+00:00");
  });

  test("should format a timestamp given as a Date", () => {
    assert.equal(timestamp(new Date("2025-04-17T21:53:17.019Z")), "2025-04-17T21:53:17.019000+00:00");
  });

  test("should add a version string field", () => {
    const result = encodeEvent({ d: "", t: "icp" });
    assert.ok(result.v.startsWith("KERI10JSON"));
  });

  test("should compute a SAID for the d field", () => {
    const result = encodeEvent({ d: "", t: "icp" });
    assert.equal(result.d.length, 44);
    assert.equal(result.d.slice(0, 1), "E");
  });

  test("should be deterministic", () => {
    const a = encodeEvent({ d: "", t: "icp", i: "abc" });
    const b = encodeEvent({ d: "", t: "icp", i: "abc" });
    assert.equal(a.d, b.d);
  });

  test("should preserve other fields", () => {
    const result = encodeEvent({ d: "", t: "icp", i: "somevalue" });
    assert.equal(result.t, "icp");
    assert.equal(result.i, "somevalue");
  });

  test("should throw if a required label is missing", () => {
    assert.throws(() => encodeEvent({ t: "icp" }), /missing label 'd'/i);
  });

  test("should support custom labels", () => {
    const result = encodeEvent({ d: "", i: "", t: "icp" }, { labels: ["d", "i"] });
    assert.equal(result.d.length, 44);
    assert.equal(result.i, result.d);
  });

  test("should encode version string with custom protocol", () => {
    const result = encodeEvent({ d: "", t: "vcp" }, { protocol: "ACDC" });
    assert.ok(result.v.startsWith("ACDC10JSON"));
  });
});
