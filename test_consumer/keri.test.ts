import assert from "node:assert";
import { describe, test } from "node:test";
import { Matter } from "cesr";
import * as surface from "keri";
import { generateKeyPair, KeyEventLog, keri, sign, verifySignature } from "keri";

describe("keri", () => {
  test("builds and verifies a key event log without storage or transport", () => {
    const current = generateKeyPair();
    const next = generateKeyPair();

    const icp = keri.incept({ signingKeys: [current.publicKey], nextKeys: [next.publicKeyDigest] });
    icp.attachments.ControllerIdxSigs.push(sign(icp.raw, { key: current.privateKey, index: 0 }));

    const log = KeyEventLog.empty().append(icp);

    assert.equal(log.state.identifier, icp.body.i);
    assert.deepEqual(log.state.signingKeys, [current.publicKey]);

    const detached = sign(icp.raw, { key: current.privateKey });
    assert.ok(verifySignature(icp.raw, Matter.parse(current.publicKey), Matter.parse(detached).raw));
  });

  // Anything added here ships to consumers forever. Infrastructure — witness, mailbox, controller,
  // transports, storage — belongs in @keri-js/infra, so a new name showing up must be deliberate.
  test("exports exactly the toolbox surface", () => {
    assert.deepEqual(Object.keys(surface).sort(), [
      "Attachments",
      "EventIndex",
      "IPEX_GRANT_ROUTE",
      "KeyEventLog",
      "Message",
      "VersionString",
      "createCredential",
      "credentialIssuee",
      "delegatedIncept",
      "delegatedRotate",
      "disclosedAttributes",
      "embeds",
      "generateKeyPair",
      "isKelEventType",
      "isTelEventType",
      "keri",
      "resolveEndRole",
      "resolveLocation",
      "sign",
      "verifyCredential",
      "verifyCredentialSaid",
      "verifyCredentials",
      "verifySignature",
      "verifyTransactionEventAnchor",
      "verifyTransactionEventSaid",
    ]);
  });

  test("exposes a single entry point", async () => {
    for (const subpath of ["keri/witness", "keri/mailbox", "keri/sqlite-storage", "keri/nodejs-utils"]) {
      await assert.rejects(() => import(subpath), `${subpath} must not resolve`);
    }
  });
});
