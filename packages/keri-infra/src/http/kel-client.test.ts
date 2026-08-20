import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeText } from "cesr";
import { generateKeyPair, KeyEvent } from "keri";
import { fetchKel, KelFetchError, KelParseError } from "./kel-client.ts";
import { sign } from "./signing.test.ts";

function makeKel(): { cesr: string; aid: string } {
  const key = generateKeyPair();
  const next = generateKeyPair();

  const event = KeyEvent.incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });
  event.attachments.ControllerIdxSigs.push(sign(event.raw, { key: key.privateKey, index: 0 }));

  return {
    cesr: new TextDecoder().decode(event.raw) + encodeText(event.attachments.frames()),
    aid: event.body.i,
  };
}

describe(basename(import.meta.url), () => {
  test("should fetch and replay a KEL", async () => {
    const { cesr, aid } = makeKel();

    const log = await fetchKel("http://witness.example/oobi/aid", { fetch: async () => new Response(cesr) });

    assert.strictEqual(log.state.identifier, aid);
    assert.strictEqual(log.state.lastEvent.s, "0");
  });

  test("should throw KelFetchError on an error status", async () => {
    await assert.rejects(
      fetchKel("http://witness.example/oobi/aid", { fetch: async () => new Response("gone", { status: 404 }) }),
      KelFetchError,
    );
  });

  test("should throw KelFetchError when the fetch itself fails", async () => {
    await assert.rejects(
      fetchKel("http://witness.example/oobi/aid", {
        fetch: async () => {
          throw new Error("connection refused");
        },
      }),
      KelFetchError,
    );
  });

  test("should throw KelFetchError for a non-http URL", async () => {
    await assert.rejects(fetchKel("file:///etc/passwd"), KelFetchError);
    await assert.rejects(fetchKel("not a url"), KelFetchError);
  });

  test("should throw KelFetchError when the response exceeds the byte cap", async () => {
    const { cesr } = makeKel();

    await assert.rejects(
      fetchKel("http://witness.example/oobi/aid", { fetch: async () => new Response(cesr), maxBytes: 16 }),
      KelFetchError,
    );
  });

  test("should throw KelParseError for a body that is not a KEL", async () => {
    await assert.rejects(
      fetchKel("http://witness.example/oobi/aid", { fetch: async () => new Response("not cesr at all") }),
      KelParseError,
    );
  });
});
