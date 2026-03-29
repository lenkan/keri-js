import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { Matter } from "cesr";
import { incept } from "./registry-event.ts";

describe("Registry", () => {
  test("Should create registry incept event", () => {
    const event = incept({
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.partialDeepStrictEqual(event.body, {
      v: "KERI10JSON0000ff_",
      t: "vcp",
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.deepEqual(Object.keys(event.body), ["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"]);
    assert.equal(event.body.i, event.body.d);
    assert.equal(event.body.n.slice(0, 2), "0A");
  });

  test("Should set NB (no backer) configuration", () => {
    const event = incept({
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.deepEqual(event.body.c, ["NB"]);
  });

  test("Should generate salt for registry event", () => {
    const event = incept({
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    const salt = Matter.parse(event.body.n);

    assert.strictEqual(salt.code, Matter.Code.Salt_128);
  });
});
