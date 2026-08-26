import assert from "node:assert";
import { basename } from "node:path";
import test, { describe } from "node:test";
import { encodeBinary, encodeText } from "./frame.ts";
import { Genus } from "./genus.ts";

describe(basename(import.meta.url), () => {
  test("should encode genus with major and minor", () => {
    const result = new Genus({ protocol: "AAA", major: 3, minor: 1239 });

    assert.strictEqual(encodeText(result), `-_AAADTX`);
    assert.deepStrictEqual(encodeBinary(result), new Uint8Array([251, 240, 0, 0, 52, 215]));
  });

  test("should encode genus without minor", () => {
    const result = new Genus({ protocol: "AAA", major: 3 });

    assert.strictEqual(encodeText(result), `-_AAADAA`);
    assert.deepStrictEqual(encodeBinary(result), new Uint8Array([251, 240, 0, 0, 48, 0]));
  });

  test("should parse genus", () => {
    const result = Genus.parse(`-_AAADTX`);

    assert.strictEqual(result.protocol, "AAA");
    assert.strictEqual(result.major, 3);
    assert.strictEqual(result.minor, 1239);
    assert.strictEqual(encodeText(result), `-_AAADTX`);
  });

  test("should have KERIACDC_10 genus", () => {
    const result = Genus.KERIACDC_10;

    assert.strictEqual(result.protocol, "AAA");
    assert.strictEqual(result.major, 1);
    assert.strictEqual(result.minor, 0);
    assert.strictEqual(encodeText(result), `-_AAABAA`);
  });

  test("should have KERIACDC_20 genus", () => {
    const result = Genus.KERIACDC_20;

    assert.strictEqual(result.protocol, "AAA");
    assert.strictEqual(result.major, 2);
    assert.strictEqual(result.minor, 0);
    assert.strictEqual(encodeText(result), `-_AAACAA`);
  });
});
