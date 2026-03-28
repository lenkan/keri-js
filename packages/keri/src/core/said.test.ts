import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { saidify } from "./said.ts";

describe("saidify", () => {
  test("returns the event unchanged when no labels provided", () => {
    const event = { d: "placeholder", foo: "bar" };
    const result = saidify(event);
    assert.deepStrictEqual(result, { d: "placeholder", foo: "bar" });
  });

  test("returns the event unchanged when labels is empty", () => {
    const event = { d: "placeholder", foo: "bar" };
    const result = saidify(event, []);
    assert.deepStrictEqual(result, { d: "placeholder", foo: "bar" });
  });

  test("replaces labeled field with computed SAID", () => {
    const result = saidify(
      {
        d: "#".repeat(44),
        foo: "bar",
        baz: "qux",
      },
      ["d"],
    );

    assert.strictEqual(result.d, "EI79ZeCJ0lOCeADL-5zxU27RQznIMcKZ5jKyxZO17X3v");
  });

  test("is deterministic for the same input", () => {
    const event = { d: "#".repeat(44), foo: "bar" };
    const a = saidify({ ...event }, ["d"]);
    const b = saidify({ ...event }, ["d"]);
    assert.strictEqual(a.d, b.d);
  });

  test("does not mutate the input object", () => {
    const event = { d: "#".repeat(44), foo: "bar" };
    saidify(event, ["d"]);
    assert.strictEqual(event.d, "#".repeat(44));
  });

  test("replaces multiple labeled fields with the same SAID", () => {
    const event = { d: "#".repeat(44), i: "#".repeat(44), s: "0" };
    const result = saidify(event, ["d", "i"]);
    assert.strictEqual(result.d, result.i);
    assert.match(result.d, /^E/);
  });

  test("preserves property order with d not first", () => {
    const event = { t: "icp", d: "#".repeat(44), s: "0" };
    const result = saidify(event, ["d"]);
    assert.deepStrictEqual(Object.keys(result), ["t", "d", "s"]);
  });

  test("preserves unlabeled fields", () => {
    const event = { d: "#".repeat(44), t: "icp", s: "0" };
    const result = saidify(event, ["d"]);
    assert.strictEqual(result.t, "icp");
    assert.strictEqual(result.s, "0");
  });
});
