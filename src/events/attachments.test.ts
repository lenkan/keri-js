import { test } from "node:test";
import { keri } from "./events.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { cesr, IndexCode, MatterCode } from "cesr/__unstable__";
import assert from "node:assert";
import { Attachments } from "./attachments.ts";
import { KeyEventMessage } from "./message.ts";

function randomKey(seed = "test"): { privateKey: Uint8Array; publicKey: string } {
  const encoder = new TextEncoder();
  const salt = blake3(encoder.encode(seed));
  const privateKey = ed25519.utils.randomSecretKey(salt);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey: cesr.encodeMatter({ code: MatterCode.Ed25519, raw: publicKey }) };
}

test("Should serialize indexed signatures", () => {
  const key0 = randomKey("test0");
  const key1 = randomKey("test1");

  const message = new KeyEventMessage(
    keri.incept({
      k: [key0.publicKey, key1.publicKey],
    }),
  );

  const attachments = new Attachments({
    sigs: [
      cesr.encodeIndexer({
        code: IndexCode.Ed25519_Sig,
        raw: ed25519.sign(message.raw, key0.privateKey),
        index: 0,
      }),
      cesr.encodeIndexer({
        code: IndexCode.Ed25519_Sig,
        raw: ed25519.sign(message.raw, key1.privateKey),
        index: 1,
      }),
    ],
  });

  assert.strictEqual(
    attachments.toString(),
    [
      "-VAt",
      "-AAC",
      "AACo9sQ34vV5dvKDn9_XT7aqXjYrQUcIXsciy84D8LslsvJTYA5X0czckvo30fSgbleGeSYRjWoDuPIyizJpOPUP",
      "ABCOpOupeb-jKCZ5geaN-qDAE0I-nNb5QWxN0UonZdpjluAQMLgWzSErlP8dE2MqzL_ScIl885AjgHN_FLSN3xgD",
    ].join(""),
  );
});

test("Should parse indexed signatures", () => {
  const attachments = Attachments.parse(
    [
      "-VAt",
      "-AAC",
      "AACo9sQ34vV5dvKDn9_XT7aqXjYrQUcIXsciy84D8LslsvJTYA5X0czckvo30fSgbleGeSYRjWoDuPIyizJpOPUP",
      "ABCOpOupeb-jKCZ5geaN-qDAE0I-nNb5QWxN0UonZdpjluAQMLgWzSErlP8dE2MqzL_ScIl885AjgHN_FLSN3xgD",
    ].join(""),
  );

  assert.deepStrictEqual(attachments.sigs, [
    "AACo9sQ34vV5dvKDn9_XT7aqXjYrQUcIXsciy84D8LslsvJTYA5X0czckvo30fSgbleGeSYRjWoDuPIyizJpOPUP",
    "ABCOpOupeb-jKCZ5geaN-qDAE0I-nNb5QWxN0UonZdpjluAQMLgWzSErlP8dE2MqzL_ScIl885AjgHN_FLSN3xgD",
  ]);
});

test("Should parse receipt couples", () => {
  const attachments = Attachments.parse(
    [
      "-VAi",
      "-CAB",
      "BEZbsFd5_-IEwhnvsaqKvPuTSm9sa9crR_ip7PU1BryR0BBWy3Amd7MoMXfG30UXr-fg6vChLBvtW0ojQqIdhE373PquVbWl4tHJYMRWbytqETC_bVMRkve9v_C9fCo1KfgN",
    ].join(""),
  );

  assert.deepStrictEqual(attachments.receipts, [
    {
      backer: "BEZbsFd5_-IEwhnvsaqKvPuTSm9sa9crR_ip7PU1BryR",
      signature: "0BBWy3Amd7MoMXfG30UXr-fg6vChLBvtW0ojQqIdhE373PquVbWl4tHJYMRWbytqETC_bVMRkve9v_C9fCo1KfgN",
    },
  ]);
});
