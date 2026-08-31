import assert from "node:assert";
import { describe, test } from "node:test";
import * as surface from "keri";
import { Credential, ed25519Signer, generateKeyPair, KeyEvent, KeyEventLog, signEvent, verifySignature } from "keri";

describe("keri", () => {
  test("builds and verifies a key event log without storage or transport", () => {
    const current = generateKeyPair();
    const next = generateKeyPair();

    const icp = KeyEvent.incept({ signingKeys: [current.publicKey], nextKeyDigests: [next.publicKeyDigest] });
    signEvent(icp, { signers: [current] });

    const log = KeyEventLog.empty().append(icp);

    assert.equal(log.state.identifier, icp.body.i);
    assert.deepEqual(log.state.signingKeys, [current.publicKey]);

    const detached = current.sign(icp.raw);
    assert.deepEqual(verifySignature(icp.raw, current.publicKey, detached), { ok: true });
  });

  // The root's verbs compose, so a signed inception reaches its log in one expression.
  test("chains construction, signing and append", () => {
    const key = generateKeyPair();
    const next = generateKeyPair();

    const log = KeyEventLog.empty().append(
      signEvent(KeyEvent.incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] }), {
        signers: [key],
      }),
    );

    assert.equal(log.state.lastEvent.s, "0");
  });

  test("adopts a private key held elsewhere", () => {
    const key = generateKeyPair();
    const adopted = ed25519Signer(key.privateKey);
    const payload = new TextEncoder().encode("payload");

    assert.equal(adopted.publicKey, key.publicKey);
    assert.deepEqual(verifySignature(payload, key.publicKey, adopted.sign(payload)), { ok: true });
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
  // Namespaces are nouns, the top level is verbs and the state they act on. The byte layer lives at
  // `keri/cesr`; only `Message` is repeated here, because every constructor returns one.
  test("exports exactly the toolbox surface", () => {
    assert.deepEqual(Object.keys(surface).sort(), [
      "Credential",
      "EventIndex",
      "KeyEvent",
      "KeyEventLog",
      "Message",
      "Registry",
      "RoutedEvent",
      "collect",
      "ed25519Signer",
      "endorse",
      "formatDate",
      "generateKeyPair",
      "nextKeyDigest",
      "saidify",
      "signEvent",
      "verify",
      "verifySignature",
    ]);
  });

  test("groups every constructor under its protocol namespace", () => {
    assert.deepEqual(Object.keys(KeyEvent).sort(), [
      "KeyEventLog",
      "applyReceipt",
      "attachSourceSeal",
      "backersFor",
      "delegatedIncept",
      "delegatedRotate",
      "incept",
      "interact",
      "isEstablishment",
      "isKeyEvent",
      "keyEventSeal",
      "receipt",
      "rotate",
      "signEvent",
    ]);

    assert.deepEqual(Object.keys(surface.Registry).sort(), ["incept", "isRegistryEvent", "issue", "revoke"]);

    assert.deepEqual(Object.keys(surface.RoutedEvent).sort(), [
      "CHALLENGE_RESPONSE_ROUTE",
      "IPEX_GRANT_ROUTE",
      "embeds",
      "endorse",
      "exchange",
      "isRoutedEvent",
      "query",
      "reply",
      "verifyExchange",
      "verifyReply",
    ]);

    assert.deepEqual(Object.keys(Credential).sort(), ["create", "disclosedAttributes", "isCredential"]);
  });

  // A namespace member and its top-level name are the same function, not two copies.
  test("namespace members and top-level verbs are the same function", () => {
    assert.equal(KeyEvent.signEvent, signEvent);
    assert.equal(KeyEvent.KeyEventLog, KeyEventLog);
    assert.equal(surface.RoutedEvent.endorse, surface.endorse);

    // The two inceptions are distinct functions told apart by their namespace.
    assert.notEqual(KeyEvent.incept, surface.Registry.incept);
  });

  // The namespaces are ES module namespaces, not classes: `KeyEvent.incept` returns a Message, so a
  // class would promise an instance type it can never produce.
  test("namespaces are module namespaces, not constructible", () => {
    for (const ns of [KeyEvent, surface.Registry, surface.RoutedEvent, Credential]) {
      assert.equal(typeof ns, "object");
      assert.throws(() => new (ns as unknown as new () => unknown)());
    }
  });

  // No per-protocol subpath: it would hand out `incept` with the namespace stripped off, the one
  // thing the grouping exists to prevent. `keri/witness` is not one — it publishes an application
  // over the primitives, not a slice of them.
  test("exposes no per-protocol entry points", async () => {
    for (const subpath of [
      "keri/key-events",
      "keri/registries",
      "keri/routed-events",
      "keri/credentials",
      "keri/encoding",
      "keri/sqlite-storage",
    ]) {
      await assert.rejects(() => import(subpath), `${subpath} must not resolve`);
    }
  });
});
