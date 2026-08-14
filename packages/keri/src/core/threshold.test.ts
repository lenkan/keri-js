import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { parseThreshold } from "./threshold.ts";

describe(basename(import.meta.url), () => {
  describe("integer threshold", () => {
    test("should assign weight 1 to each key and set required to threshold", () => {
      assert.deepEqual(parseThreshold("1", 3), { weights: [1, 1, 1], required: 1 });
      assert.deepEqual(parseThreshold("2", 3), { weights: [1, 1, 1], required: 2 });
      assert.deepEqual(parseThreshold("3", 3), { weights: [1, 1, 1], required: 3 });
    });

    test("should throw when threshold exceeds number of keys", () => {
      assert.throws(() => parseThreshold("4", 3), {
        message: "Invalid threshold: 4 exceeds number of parties: 3",
      });
    });

    test("should throw on non-positive value", () => {
      assert.throws(() => parseThreshold("0", 2), { message: "Invalid threshold: 0" });
      assert.throws(() => parseThreshold("-1", 2), { message: "Invalid threshold: -1" });
    });

    test("should throw on non-integer value", () => {
      assert.throws(() => parseThreshold("1.5", 2), { message: "Invalid threshold: 1.5" });
      assert.throws(() => parseThreshold("invalid", 2), { message: "Invalid threshold: invalid" });
    });
  });

  describe("fractional threshold", () => {
    test("should scale weights to a common required", () => {
      assert.deepEqual(parseThreshold(["1/2", "1/3"], 2), { weights: [3, 2], required: 6 });
      assert.deepEqual(parseThreshold(["1/2", "1/4"], 2), { weights: [2, 1], required: 4 });
    });

    test("should throw on malformed fraction", () => {
      assert.throws(() => parseThreshold(["1/"], 1), { message: "Invalid threshold: 1/" });
      assert.throws(() => parseThreshold(["/2"], 1), { message: "Invalid threshold: /2" });
    });

    test("should throw on non-positive fraction parts", () => {
      assert.throws(() => parseThreshold(["0/2"], 1), { message: "Invalid threshold: 0/2" });
      assert.throws(() => parseThreshold(["1/0"], 1), { message: "Invalid threshold: 1/0" });
    });
  });
});
