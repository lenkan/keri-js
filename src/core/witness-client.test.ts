import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeText, Message } from "#keri/cesr";
import { incept, type KeyEvent } from "./key-event.ts";
import { generateKeyPair, type KeyPair } from "./keys.ts";
import { receipt } from "./receipt-event.ts";
import { sign } from "./sign.ts";
import { WitnessClient } from "./witness-client.ts";

function makeEvent() {
  const sigKey = generateKeyPair();
  const witnessKey = generateKeyPair({ nonTransferable: true });

  const event = incept({
    signingKeys: [sigKey.publicKey],
    nextKeys: [],
    wits: [witnessKey.publicKey],
  });

  event.attachments.ControllerIdxSigs.push(sign(event.raw, { key: sigKey.privateKey, index: 0 }));

  return { event, sigKey, witnessKey };
}

function makeReceiptResponse(event: KeyEvent, witnessKey: KeyPair) {
  const rct = receipt({ d: event.body.d, i: event.body.i, s: event.body.s });
  const witnessSig = sign(event.raw, { key: witnessKey.privateKey });
  const receiptMsg = new Message(rct.body, {
    NonTransReceiptCouples: [{ prefix: witnessKey.publicKey, sig: witnessSig }],
  });
  return JSON.stringify(receiptMsg.body) + encodeText(receiptMsg.attachments.frames());
}

describe(basename(import.meta.url), () => {
  describe("receipt()", () => {
    test("should return the receipt when the witness signature is valid", async () => {
      const { event, witnessKey } = makeEvent();
      const body = makeReceiptResponse(event, witnessKey);

      const client = new WitnessClient("http://witness.example", async () => new Response(body));
      const rct = await client.receipt(event);

      assert.strictEqual(rct.body.t, "rct");
      assert.strictEqual(rct.body.d, event.body.d);
      assert.strictEqual(rct.attachments.NonTransReceiptCouples[0].prefix, witnessKey.publicKey);
    });

    test("should throw when the witness signature is invalid", async () => {
      const { event, witnessKey } = makeEvent();
      const attackerKey = generateKeyPair({ nonTransferable: true });

      const rct = receipt({ d: event.body.d, i: event.body.i, s: event.body.s });
      const badSig = sign(event.raw, { key: attackerKey.privateKey });
      const receiptMsg = new Message(rct.body, {
        NonTransReceiptCouples: [{ prefix: witnessKey.publicKey, sig: badSig }],
      });
      const body = JSON.stringify(receiptMsg.body) + encodeText(receiptMsg.attachments.frames());

      const client = new WitnessClient("http://witness.example", async () => new Response(body));
      await assert.rejects(() => client.receipt(event), /Invalid witness signature from/);
    });

    test("should throw when the response is not OK", async () => {
      const { event } = makeEvent();

      const client = new WitnessClient(
        "http://witness.example",
        async () => new Response("Bad Request", { status: 400 }),
      );
      await assert.rejects(() => client.receipt(event), /Failed to submit event to witness/);
    });

    test("should throw when no matching receipt is returned", async () => {
      const { event } = makeEvent();

      const client = new WitnessClient("http://witness.example", async () => new Response(""));
      await assert.rejects(() => client.receipt(event), /No receipt returned from/);
    });

    test("should throw for non-http protocols", async () => {
      const { event } = makeEvent();

      const client = new WitnessClient("ftp://witness.example", async () => new Response(""));
      await assert.rejects(() => client.receipt(event), /Invalid protocol/);
    });
  });
});
