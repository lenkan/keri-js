import assert from "node:assert";
import { describe, test } from "node:test";
import { generateKeyPair, KeyEvent, signEvent } from "keri";
import { Attachments, encodeText, Matter, parse } from "keri/cesr";
import { MemoryStore, Witness } from "keri/witness";

describe("keri/witness", () => {
  test("receipts a key event over its own fetch handler", async () => {
    const witness = new Witness({
      privateKey: generateKeyPair().privateKey,
      url: "http://localhost:5631",
      store: new MemoryStore(),
    });

    const current = generateKeyPair();
    const next = generateKeyPair();
    const icp = KeyEvent.incept({
      signingKeys: [current.publicKey],
      nextKeyDigests: [next.publicKeyDigest],
      backers: [witness.aid],
    });
    signEvent(icp, { signers: [current] });

    const response = await witness.fetch(
      new Request("http://localhost:5631/receipts", {
        method: "POST",
        body: new TextDecoder().decode(icp.raw),
        headers: {
          "CESR-ATTACHMENT": encodeText(
            new Attachments({ ControllerIdxSigs: icp.attachments.ControllerIdxSigs }).frames(),
          ),
        },
      }),
    );

    assert.strictEqual(response.status, 200);

    const [receipt] = await Array.fromAsync(parse(response.body ?? new Uint8Array()));
    assert.strictEqual(receipt.body.t, "rct");
    assert.strictEqual(receipt.body.d, icp.body.d);

    const couple = receipt.attachments.NonTransReceiptCouples[0];
    assert.strictEqual(couple.prefix, witness.aid);
    assert.strictEqual(Matter.parse(couple.sig).raw.length, 64);
  });

  test("serves the receipted identifier back as an OOBI", async () => {
    const witness = new Witness({
      privateKey: generateKeyPair().privateKey,
      url: "http://localhost:5631",
      store: new MemoryStore(),
    });

    const current = generateKeyPair();
    const next = generateKeyPair();
    const icp = KeyEvent.incept({
      signingKeys: [current.publicKey],
      nextKeyDigests: [next.publicKeyDigest],
      backers: [witness.aid],
    });
    signEvent(icp, { signers: [current] });

    await witness.fetch(
      new Request("http://localhost:5631/receipts", {
        method: "POST",
        body: new TextDecoder().decode(icp.raw),
        headers: {
          "CESR-ATTACHMENT": encodeText(
            new Attachments({ ControllerIdxSigs: icp.attachments.ControllerIdxSigs }).frames(),
          ),
        },
      }),
    );

    const response = await witness.fetch(new Request(`http://localhost:5631/oobi/${icp.body.i}`));
    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers.get("Keri-Aid"), icp.body.i);

    const [stored] = await Array.fromAsync(parse(response.body ?? new Uint8Array()));
    assert.strictEqual(stored.body.i, icp.body.i);
    assert.strictEqual(stored.attachments.WitnessIdxSigs.length, 1);
  });
});
