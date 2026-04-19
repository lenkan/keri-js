import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeBinary, encodeText } from "./frame.ts";

describe(basename(import.meta.url), () => {
  const SIZE = { hs: 1, ss: 0, fs: 44, ls: 0 };

  describe("encodeText", () => {
    test("encodes 32 zero bytes with code B", () => {
      const raw = new Uint8Array(32);
      const result = encodeText({ code: "B", size: SIZE, raw });
      assert.strictEqual(result.length, 44);
      assert.ok(result.startsWith("B"));
      assert.strictEqual(result, `B${"A".repeat(43)}`);
    });

    test("throws if code length does not match hs", () => {
      const raw = new Uint8Array(32);
      assert.throws(() => encodeText({ code: "BB", size: SIZE, raw }), /does not match expected size/);
    });

    test("encodes array of frames by concatenation", () => {
      const raw = new Uint8Array(32);
      const frame = { code: "B", size: SIZE, raw };
      const single = encodeText(frame);
      const result = encodeText([frame, frame]);
      assert.strictEqual(result, single + single);
    });
  });

  describe("encodeBinary", () => {
    test("encodes 32 zero bytes with code B", () => {
      const raw = new Uint8Array(32);
      const result = encodeBinary({ code: "B", size: SIZE, raw });
      assert.strictEqual(result.byteLength, 33);
      assert.strictEqual(result[0], 4);
      for (let i = 1; i < result.byteLength; i++) {
        assert.strictEqual(result[i], 0);
      }
    });

    test("produces output of correct length without raw", () => {
      const result = encodeBinary({ code: "B", size: SIZE });
      assert.strictEqual(result.byteLength, 1);
    });
  });
});
