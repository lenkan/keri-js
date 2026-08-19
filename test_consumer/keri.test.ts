import assert from "node:assert";
import { describe, test } from "node:test";
import * as surface from "keri";
import { Credential, ed25519Signer, generateKeyPair, KeyEvent, KeyEventLog, signEvent, verifySignature } from "keri";

describe("keri", () => {
  test("builds and verifies a key event log without storage or transport", async () => {
    const current = generateKeyPair();
    const next = generateKeyPair();
    const signer = ed25519Signer(current.privateKey);

    const icp = KeyEvent.incept({ signingKeys: [current.publicKey], nextKeyDigests: [next.publicKeyDigest] });
    await signEvent(icp, [signer]);

    const log = KeyEventLog.empty().append(icp);

    assert.equal(log.state.identifier, icp.body.i);
    assert.deepEqual(log.state.signingKeys, [current.publicKey]);

    const detached = await signer.sign(icp.raw);
    assert.deepEqual(verifySignature(icp.raw, current.publicKey, detached), { ok: true });
  });

  test("builds an ACDC and reads back its disclosed claims", () => {
    const issuer = generateKeyPair();

    const acdc = Credential.from({
      i: issuer.publicKey,
      ri: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      s: "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
      a: { i: issuer.publicKey, LEI: "5493001KJTIIGC8Y1R17" },
      r: {},
    });

    assert.ok(Credential.isCredential(acdc));
    assert.deepEqual(Credential.disclosedAttributes(acdc.body), [["LEI", "5493001KJTIIGC8Y1R17"]]);
  });

  // Anything added here ships to consumers forever. Infrastructure — witness, mailbox, controller,
  // transports, storage — belongs in @keri-js/infra, so a new name showing up must be deliberate.
  //
  // Constructors live on the four namespaces, not as flat exports. Adding flat aliases later would
  // be additive, but shipping both is the duplication this surface was reshaped to remove.
  test("exports exactly the toolbox surface", () => {
    assert.deepEqual(Object.keys(surface).sort(), [
      "Attachments",
      "Counter",
      "Credential",
      "EventIndex",
      "Indexer",
      "KeyEvent",
      "KeyEventLog",
      "Matter",
      "Message",
      "RoutedEvent",
      "TransactionEvent",
      "VersionString",
      "collect",
      "ed25519Signer",
      "formatDate",
      "generateKeyPair",
      "nextKeyDigest",
      "parse",
      "saidify",
      "signEvent",
      "verify",
      "verifySignature",
    ]);
  });

  test("groups every constructor under its protocol namespace", () => {
    assert.deepEqual(
      Object.getOwnPropertyNames(KeyEvent)
        .filter((name) => !["length", "name", "prototype"].includes(name))
        .sort(),
      ["delegatedIncept", "delegatedRotate", "incept", "interact", "isKeyEvent", "receipt", "rotate"],
    );

    assert.deepEqual(
      Object.getOwnPropertyNames(surface.TransactionEvent)
        .filter((name) => !["length", "name", "prototype"].includes(name))
        .sort(),
      ["incept", "isTransactionEvent", "issue", "revoke"],
    );

    assert.deepEqual(
      Object.getOwnPropertyNames(surface.RoutedEvent)
        .filter((name) => !["length", "name", "prototype"].includes(name))
        .sort(),
      ["IPEX_GRANT_ROUTE", "embeds", "exchange", "isRoutedEvent", "query", "reply"],
    );

    assert.deepEqual(
      Object.getOwnPropertyNames(Credential)
        .filter((name) => !["length", "name", "prototype"].includes(name))
        .sort(),
      ["disclosedAttributes", "from", "isCredential"],
    );
  });

  test("exposes a single entry point", async () => {
    for (const subpath of ["keri/witness", "keri/mailbox", "keri/sqlite-storage", "keri/nodejs-utils"]) {
      await assert.rejects(() => import(subpath), `${subpath} must not resolve`);
    }
  });
});
