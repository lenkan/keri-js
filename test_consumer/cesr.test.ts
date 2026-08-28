import assert from "node:assert";
import { createReadStream } from "node:fs";
import { describe, test } from "node:test";
import { decodeBase64Url, encodeBase64Url, encodeText, Matter, parse } from "keri/cesr";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url);

describe("cesr", () => {
  test("parses a key event log stream", async () => {
    const messages = await Array.fromAsync(parse(createReadStream(fixture("alice.cesr"))));

    assert.equal(messages.length, 2);
    assert.equal(messages[0]?.body.t, "icp");
    assert.equal(messages[0].attachments.ControllerIdxSigs.length, 1);
  });

  test("round-trips a primitive through encodeText and Matter.parse", () => {
    const digest = Matter.crypto.blake3_256(new Uint8Array(32));
    const text = encodeText(digest);

    assert.equal(text.length, 44);
    assert.deepEqual(Matter.parse(text).raw, digest.raw);
  });
});

describe("cesr encoding helpers", () => {
  test("round-trips bytes through base64url", () => {
    const raw = Uint8Array.from([0, 1, 2, 250, 251, 252]);

    assert.deepEqual(decodeBase64Url(encodeBase64Url(raw)), raw);
  });
});
