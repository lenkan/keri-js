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

    const acdc = Credential.create({
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
  // Constructors reach the root only through the four namespaces. They are not also flat exports
  // here: the same function is available loose from its subpath, under the same name.
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
    assert.deepEqual(Object.keys(KeyEvent).sort(), [
      "delegatedIncept",
      "delegatedRotate",
      "incept",
      "interact",
      "isEstablishment",
      "isKeyEvent",
      "receipt",
      "rotate",
    ]);

    assert.deepEqual(Object.keys(surface.TransactionEvent).sort(), ["incept", "isTransactionEvent", "issue", "revoke"]);

    assert.deepEqual(Object.keys(surface.RoutedEvent).sort(), [
      "CHALLENGE_RESPONSE_ROUTE",
      "IPEX_GRANT_ROUTE",
      "embeds",
      "exchange",
      "isRoutedEvent",
      "query",
      "reply",
      "verifyExchange",
    ]);

    assert.deepEqual(Object.keys(Credential).sort(), ["create", "disclosedAttributes", "isCredential"]);
  });

  // The namespaces are ES module namespaces, not classes: `KeyEvent.incept` returns a Message, so a
  // class would promise an instance type it can never produce.
  test("namespaces are module namespaces, not constructible", () => {
    for (const ns of [KeyEvent, surface.TransactionEvent, surface.RoutedEvent, Credential]) {
      assert.equal(typeof ns, "object");
      assert.throws(() => new (ns as unknown as new () => unknown)());
    }
  });

  // Each namespace member is also importable one at a time, under the same name.
  test("subpaths expose the same functions loose", async () => {
    const [keyEvents, transactionEvents, routedEvents, credentials] = await Promise.all([
      import("keri/key-events"),
      import("keri/transaction-events"),
      import("keri/routed-events"),
      import("keri/credentials"),
    ]);

    assert.equal(keyEvents.incept, KeyEvent.incept);
    assert.equal(transactionEvents.incept, surface.TransactionEvent.incept);
    assert.equal(routedEvents.reply, surface.RoutedEvent.reply);
    assert.equal(credentials.create, Credential.create);

    // The two inceptions are distinct functions reached under one name from different paths.
    assert.notEqual(keyEvents.incept, transactionEvents.incept);
  });

  test("exposes no other entry points", async () => {
    for (const subpath of ["keri/witness", "keri/mailbox", "keri/sqlite-storage", "keri/nodejs-utils"]) {
      await assert.rejects(() => import(subpath), `${subpath} must not resolve`);
    }
  });
});
