import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Message } from "../cesr/main.ts";
import { isReceipt, receipt } from "./receipt-event.ts";

describe(basename(import.meta.url), () => {
  describe("isReceipt", () => {
    test("should return true for rct produced by receipt()", () => {
      const m = receipt({ d: "EAAAAAAA", i: "EBBBBBBB", s: "0" });
      assert.equal(isReceipt(m), true);
    });

    test("should return false for non-rct message types", () => {
      const stub = (t: string) => new Message({ v: "KERI10JSON000000_", t, d: "", i: "" } as never);
      assert.equal(isReceipt(stub("icp")), false);
      assert.equal(isReceipt(stub("rpy")), false);
      assert.equal(isReceipt(stub("exn")), false);
    });
  });
});
