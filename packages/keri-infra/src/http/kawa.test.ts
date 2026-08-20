import assert from "node:assert";
import { basename } from "node:path";
import { describe, mock, test } from "node:test";
import { encodeText, Message } from "cesr";
import { generateKeyPair, KeyEvent } from "keri";
import type { WitnessEndpoint } from "./kawa.ts";
import { submitToWitnesses } from "./kawa.ts";
import { sign } from "./signing.test.ts";

function createResponse(body: Message): Response {
  const serialized = JSON.stringify(body.body) + encodeText(body.attachments.frames());
  return new Response(serialized);
}

describe(basename(import.meta.url), () => {
  test("should return witness indexed signature for single witness", async () => {
    const sigKey = generateKeyPair();
    const nextKey = generateKeyPair();
    const witnessKey = generateKeyPair({ nonTransferable: true });

    const event = KeyEvent.incept({
      signingKeys: [sigKey.publicKey],
      nextKeyDigests: [nextKey.publicKeyDigest],
      backers: [witnessKey.publicKey],
    });

    event.attachments.ControllerIdxSigs.push(sign(event.raw, { key: sigKey.privateKey, index: 0 }));

    const rct = KeyEvent.receipt(event);
    const witnessSig = sign(event.raw, { key: witnessKey.privateKey });
    const receiptMsg = new Message(rct.body, {
      NonTransReceiptCouples: [{ prefix: witnessKey.publicKey, sig: witnessSig }],
    });

    const fetchMock = mock.method(globalThis, "fetch", async () => createResponse(receiptMsg));

    const endpoint: WitnessEndpoint = {
      aid: witnessKey.publicKey,
      url: "http://witness.example",
    };

    const wigs = await submitToWitnesses(event, [endpoint], fetchMock);

    assert.strictEqual(
      fetchMock.mock.calls.length,
      1,
      "Only one fetch call (no mailbox distribution for single witness)",
    );
    const callUrl = String(fetchMock.mock.calls[0]?.arguments[0]);
    assert.ok(callUrl.endsWith("/receipts"), `Expected URL to end with /receipts, got ${callUrl}`);
    assert.strictEqual(wigs.length, 1);
    assert.ok(wigs[0].length > 0, "Expected non-empty CESR-encoded indexed witness signature");
  });

  test("should reject receipt with invalid witness signature", async () => {
    const sigKey = generateKeyPair();
    const nextKey = generateKeyPair();
    const witnessKey = generateKeyPair({ nonTransferable: true });
    const attackerKey = generateKeyPair({ nonTransferable: true });

    const event = KeyEvent.incept({
      signingKeys: [sigKey.publicKey],
      nextKeyDigests: [nextKey.publicKeyDigest],
      backers: [witnessKey.publicKey],
    });

    event.attachments.ControllerIdxSigs.push(sign(event.raw, { key: sigKey.privateKey, index: 0 }));

    const rct = KeyEvent.receipt(event);
    const invalidSig = sign(event.raw, { key: attackerKey.privateKey });
    const receiptMsg = new Message(rct.body, {
      NonTransReceiptCouples: [{ prefix: witnessKey.publicKey, sig: invalidSig }],
    });

    const fetchMock = mock.method(globalThis, "fetch", async () => createResponse(receiptMsg));

    const endpoint: WitnessEndpoint = {
      aid: witnessKey.publicKey,
      url: "http://witness.example",
    };

    await assert.rejects(() => submitToWitnesses(event, [endpoint], fetchMock), /Invalid witness signature from/);
  });
});
