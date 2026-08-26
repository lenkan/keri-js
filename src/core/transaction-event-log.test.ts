import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Message, parse } from "../cesr/main.ts";
import type { IssueEventBody } from "./credential-event.ts";
import type { KeyEventBody } from "./key-event.ts";
import { isKelEventType } from "./key-event.ts";
import { KeyEventLog } from "./key-event-log.ts";
import type { RegistryInceptEventBody } from "./registry-event.ts";
import type { TransactionEventBody } from "./transaction-event-log.ts";
import {
  isTelEventType,
  resolveCredentialTel,
  verifyTransactionEventAnchor,
  verifyTransactionEventSaid,
} from "./transaction-event-log.ts";

const REGISTRY = "EEXV71avZSL6fKJnQky_oxHqRPlNYR3zNGD-OpJe0DJa";
const CREDENTIAL = "EKBG6wNsN9iT_gujAjOytqAyQdwtA24qc5C96xgu6Qy9";

interface Fixture {
  issuer: KeyEventLog;
  vcp: Message<RegistryInceptEventBody>;
  iss: Message<IssueEventBody>;
}

async function loadFixture(): Promise<Fixture> {
  const bytes = new Uint8Array(await readFile(new URL("../../fixtures/credential.cesr", import.meta.url)));
  const messages = await Array.fromAsync(parse(bytes));

  const keyEvents = messages.filter((m) => isKelEventType(m.body.t)) as Message<KeyEventBody>[];
  const vcp = messages.find((m) => m.body.t === "vcp") as Message<RegistryInceptEventBody>;
  const iss = messages.find((m) => m.body.t === "iss") as Message<IssueEventBody>;

  return { issuer: KeyEventLog.fromMessages(keyEvents), vcp, iss };
}

describe(basename(import.meta.url), () => {
  test("should identify transaction event types", () => {
    assert.ok(isTelEventType("vcp"));
    assert.ok(isTelEventType("iss"));
    assert.ok(isTelEventType("rev"));
    assert.equal(isTelEventType("ixn"), false);
    assert.equal(isTelEventType(undefined), false);
  });

  test("should verify the said of a keripy vcp over both d and i", async () => {
    const { vcp } = await loadFixture();
    assert.deepEqual(verifyTransactionEventSaid(vcp.body), { ok: true });
  });

  test("should verify the said of a keripy iss", async () => {
    const { iss } = await loadFixture();
    assert.deepEqual(verifyTransactionEventSaid(iss.body), { ok: true });
  });

  test("should reject a vcp whose nonce was altered", async () => {
    const { vcp } = await loadFixture();
    const tampered = { ...vcp.body, n: "0AAr75cmjijU8_h_MYwJAwuX" };

    const result = verifyTransactionEventSaid(tampered);
    assert.equal(result.ok, false);
    assert.match(result.error ?? "", /SAID mismatch on 'd' for vcp/);
  });

  test("should reject an iss whose timestamp was altered", async () => {
    const { iss } = await loadFixture();
    const tampered = { ...iss.body, dt: "2026-01-01T00:00:00.000000+00:00" };

    const result = verifyTransactionEventSaid(tampered);
    assert.equal(result.ok, false);
  });

  test("should not mutate the event it verifies", async () => {
    const { iss } = await loadFixture();
    const before = JSON.stringify(iss.body);

    verifyTransactionEventSaid(iss.body);

    assert.equal(JSON.stringify(iss.body), before);
  });

  test("should verify the anchors of a keripy vcp and iss", async () => {
    const { issuer, vcp, iss } = await loadFixture();

    assert.deepEqual(verifyTransactionEventAnchor(vcp, issuer), { ok: true });
    assert.deepEqual(verifyTransactionEventAnchor(iss, issuer), { ok: true });
  });

  test("should reject an anchor hint pointing at an event outside the issuer kel", async () => {
    const { issuer, iss } = await loadFixture();
    const tampered = new Message(iss.body, {
      SealSourceCouples: [{ snu: "2", digest: "EJIHL_dGqxLeLVHg8gFTpbiQ15VoUjUGR6t0hI3ffWaX" }],
    });

    const result = verifyTransactionEventAnchor(tampered, issuer);
    assert.equal(result.ok, false);
    assert.match(result.error ?? "", /Anchoring event not in issuer KEL/);
  });

  test("should reject an anchor hint pointing at the wrong issuer event", async () => {
    const { issuer, iss, vcp } = await loadFixture();
    // The ixn that anchors the vcp does not anchor the iss.
    const registryAnchor = vcp.attachments.SealSourceCouples[0];
    const tampered = new Message(iss.body, { SealSourceCouples: [registryAnchor] });

    const result = verifyTransactionEventAnchor(tampered, issuer);
    assert.equal(result.ok, false);
    assert.match(result.error ?? "", /does not anchor iss/);
  });

  // keripy does not always transmit the couple, so the anchor must still be
  // found by scanning the issuer's KEL.
  test("should find the anchor by scanning when no hint is attached", async () => {
    const { issuer, iss } = await loadFixture();
    const stripped = new Message(iss.body);

    assert.deepEqual(verifyTransactionEventAnchor(stripped, issuer), { ok: true });
  });

  test("should report a missing anchor when no issuer event carries the seal", async () => {
    const { issuer, iss } = await loadFixture();
    const unanchored = new Message({ ...iss.body, d: "EEUs6vfVMrXAwWmJAKX1yWtQTJ6AhCIEQF1K_HEXdNLX" });

    const result = verifyTransactionEventAnchor(unanchored, issuer);
    assert.equal(result.ok, false);
    assert.match(result.error ?? "", /No anchoring event in issuer KEL/);
  });

  test("should resolve the tel for the fixture credential", async () => {
    const { vcp, iss } = await loadFixture();
    const events: Message<TransactionEventBody>[] = [vcp, iss];

    const tel = resolveCredentialTel(events, { credential: CREDENTIAL, registry: REGISTRY });

    assert.equal(tel.registry?.body.d, vcp.body.d);
    assert.equal(tel.issuance?.body.d, iss.body.d);
    assert.equal(tel.revocation, null);
    assert.equal(tel.status, "issued");
  });

  test("should report unknown status for a credential with no issuance", async () => {
    const { vcp, iss } = await loadFixture();
    const events: Message<TransactionEventBody>[] = [vcp, iss];

    const tel = resolveCredentialTel(events, { credential: "EOther", registry: REGISTRY });

    assert.equal(tel.issuance, null);
    assert.equal(tel.status, "unknown");
  });
});
