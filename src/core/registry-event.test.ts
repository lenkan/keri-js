import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Matter, Message } from "../cesr/main.ts";
import { incept, isRegistryInception } from "./registry-event.ts";

describe(basename(import.meta.url), () => {
  test("should create registry incept event", () => {
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

  test("should set NB (no backer) configuration", () => {
    const event = incept({
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    assert.deepEqual(event.body.c, ["NB"]);
  });

  test("should generate salt for registry event", () => {
    const event = incept({
      ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3",
    });

    const salt = Matter.parse(event.body.n);

    assert.strictEqual(salt.code, Matter.Code.Salt_128);
  });

  describe("isRegistryInception", () => {
    test("should return true for vcp produced by incept()", () => {
      const event = incept({ ii: "EGpWO66krJQ5KqdGbB35e_V_vF0BfHR8APf__IkZEkI3" });
      assert.equal(isRegistryInception(event), true);
    });

    test("should return false for non-vcp message types", () => {
      const stub = (t: string) => new Message({ v: "KERI10JSON000000_", t, d: "", i: "" } as never);
      assert.equal(isRegistryInception(stub("icp")), false);
      assert.equal(isRegistryInception(stub("rct")), false);
      assert.equal(isRegistryInception(stub("iss")), false);
    });
  });
});
