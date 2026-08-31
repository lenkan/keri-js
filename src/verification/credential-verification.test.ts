import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { signWith } from "../../test_utils/signing.ts";
import { Message, parse } from "../cesr/main.ts";
import { type CredentialBody, create as createCredential } from "../credentials/main.ts";
import { incept, interact, KeyEventLog } from "../key-events/main.ts";
import { generateKeyPair } from "../keys/main.ts";
import { type IssueEventBody, issue, incept as registry, revoke } from "../registries/main.ts";
import type { CheckStatus, CredentialCheckId, CredentialVerification } from "./credential-verification.ts";
import { verifyCredential, verifyCredentials } from "./credential-verification.ts";
import { EventIndex } from "./event-index.ts";

const SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const OTHER_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";
const DT = "2026-01-01T00:00:00.000000+00:00";
const CREDENTIAL = "EKBG6wNsN9iT_gujAjOytqAyQdwtA24qc5C96xgu6Qy9";

function statuses(result: CredentialVerification): [CredentialCheckId, CheckStatus][] {
  return result.checks.map((check) => [check.id, check.status]);
}

function status(result: CredentialVerification, id: CredentialCheckId): CheckStatus | undefined {
  return result.checks.find((check) => check.id === id)?.status;
}

function detail(result: CredentialVerification, id: CredentialCheckId): string {
  return result.checks.find((check) => check.id === id)?.detail ?? "";
}

async function fixtureMessages(name: string): Promise<Message[]> {
  const bytes = new Uint8Array(await readFile(new URL(`../../fixtures/${name}`, import.meta.url)));
  return Array.fromAsync(parse(bytes));
}

/** The fixture index, optionally with its ACDC body rewritten in place. */
async function fixtureIndex(mutate?: (body: CredentialBody) => CredentialBody): Promise<EventIndex> {
  const messages = await fixtureMessages("credential.cesr");
  if (!mutate) {
    return new EventIndex(messages);
  }

  return new EventIndex(
    messages.map((message) =>
      message.version.protocol === "ACDC"
        ? new Message(mutate(structuredClone(message.body as CredentialBody)), message.attachments)
        : message,
    ),
  );
}

/**
 * An issuer with a registry, able to issue chained and revoked credentials.
 * keripy has never produced a `rev` or edge fixture for this repo, so those
 * paths are covered for self-consistency only.
 */
function newIssuer() {
  const key = generateKeyPair();
  const next = generateKeyPair();
  const sign = (event: Message) => signWith(event, [key]);

  const icp = incept({ signingKeys: [key.publicKey], nextKeyDigests: [next.publicKeyDigest] });
  const icpMessage = new Message(icp.body, { ControllerIdxSigs: sign(icp) });
  const messages: Message[] = [icpMessage];
  let log = KeyEventLog.empty().append(icpMessage);

  const anchor = (seal: { i: string; s: string; d: string }) => {
    const ixn = interact(log.state, { data: seal });
    const message = new Message(ixn.body, { ControllerIdxSigs: sign(ixn) });
    log = log.append(message);
    messages.push(message);
    return { snu: ixn.body.s, digest: ixn.body.d };
  };

  const vcp = registry({ ii: log.state.identifier });
  messages.push(
    new Message(vcp.body, { SealSourceCouples: [anchor({ i: vcp.body.i, s: vcp.body.s, d: vcp.body.d })] }),
  );

  return {
    aid: log.state.identifier,
    registry: vcp.body.i,
    messages,

    issue(args: { schema?: string; edges?: Record<string, unknown> } = {}) {
      const credential = createCredential({
        i: log.state.identifier,
        ri: vcp.body.i,
        s: args.schema ?? SCHEMA,
        a: { i: log.state.identifier, dt: DT, LEI: "123123123" },
        r: {},
        ...(args.edges && { e: args.edges }),
      });

      const iss = issue({ i: credential.body.d, ri: vcp.body.i, dt: new Date(DT) });
      const couple = anchor({ i: iss.body.i, s: iss.body.s, d: iss.body.d });
      messages.push(credential, new Message(iss.body, { SealSourceCouples: [couple] }));

      return { credential, iss };
    },

    revoke(credential: Message<CredentialBody>, iss: Message<IssueEventBody>) {
      const rev = revoke({ i: credential.body.d, ri: vcp.body.i, p: iss.body.d });
      const couple = anchor({ i: rev.body.i, s: rev.body.s, d: rev.body.d });
      messages.push(new Message(rev.body, { SealSourceCouples: [couple] }));
      return rev;
    },
  };
}

describe(basename(import.meta.url), () => {
  test("should verify a keripy issued credential end to end", async () => {
    const result = verifyCredential(await fixtureIndex(), CREDENTIAL);

    assert.deepEqual(statuses(result), [
      ["acdc-said", "passed"],
      ["acdc-section-saids", "passed"],
      ["issuer-kel", "passed"],
      ["registry-inception", "passed"],
      ["registry-anchor", "passed"],
      ["issuance", "passed"],
      ["issuance-anchor", "passed"],
      ["revocation-anchor", "not-applicable"],
      ["edges", "not-applicable"],
      ["schema", "unchecked"],
    ]);
    assert.equal(result.ok, true);
    assert.equal(result.status, "issued");
    assert.equal(result.issuedAt, "2025-04-17T21:53:17.019676+00:00");
    assert.equal(result.revokedAt, null);
    assert.equal(result.issuee, "EOdUAG4xgTpDeV8eMf1aZuFmaSOjMvDRcdpvAO48TM9A");
    assert.deepEqual(result.edges, []);
  });

  // The schema document cannot be resolved offline, so this must never read as passed.
  test("should never report the schema check as passed", async () => {
    const result = verifyCredential(await fixtureIndex(), CREDENTIAL);

    assert.equal(status(result, "schema"), "unchecked");
    assert.equal(result.ok, true);
  });

  test("should verify every credential in the index", async () => {
    const results = verifyCredentials(await fixtureIndex());

    assert.equal(results.length, 1);
    assert.equal(results[0].said, CREDENTIAL);
  });

  test("should throw for a said that is not in the index", async () => {
    const index = await fixtureIndex();

    assert.throws(() => verifyCredential(index, "EUnknown"), TypeError);
  });

  test("should fail both said checks when an attribute is altered", async () => {
    const index = await fixtureIndex((body) => {
      (body.a as Record<string, unknown>).LEI = "999999999";
      return body;
    });

    const result = verifyCredential(index, CREDENTIAL);

    assert.equal(result.ok, false);
    assert.equal(status(result, "acdc-said"), "failed");
    assert.equal(status(result, "acdc-section-saids"), "failed");
    assert.match(detail(result, "acdc-section-saids"), /Section 'a' SAID mismatch/);
  });

  test("should fail only the body said when a top level field is altered", async () => {
    const index = await fixtureIndex((body) => ({ ...body, s: OTHER_SCHEMA }));

    const result = verifyCredential(index, CREDENTIAL);

    assert.equal(status(result, "acdc-said"), "failed");
    assert.equal(status(result, "acdc-section-saids"), "passed");
  });

  test("should skip the anchor checks when the issuer kel does not verify", async () => {
    const messages = await fixtureMessages("credential.cesr");
    const index = new EventIndex(
      messages.map((message) => (message.body.t === "icp" ? new Message(message.body) : message)),
    );

    const result = verifyCredential(index, CREDENTIAL);

    assert.equal(result.ok, false);
    assert.equal(result.status, "unknown");
    assert.equal(result.issuerState, null);
    assert.equal(status(result, "issuer-kel"), "failed");
    assert.equal(status(result, "registry-anchor"), "skipped");
    assert.equal(status(result, "issuance-anchor"), "skipped");
  });

  test("should fail when the issuer has no key events in the index", async () => {
    const messages = await fixtureMessages("credential.cesr");
    const index = new EventIndex(messages.filter((message) => message.body.t !== "icp" && message.body.t !== "ixn"));

    const result = verifyCredential(index, CREDENTIAL);

    assert.equal(status(result, "issuer-kel"), "failed");
    assert.match(detail(result, "issuer-kel"), /No key events for issuer/);
  });

  // A stream that simply omits the issuance must not compute as verified.
  test("should fail when no registry events are present", async () => {
    const messages = await fixtureMessages("credential.cesr");
    const index = new EventIndex(
      messages.filter(
        (message) => message.version.protocol !== "KERI" || message.body.t === "icp" || message.body.t === "ixn",
      ),
    );

    const result = verifyCredential(index, CREDENTIAL);

    assert.equal(result.ok, false);
    assert.equal(result.status, "unknown");
    assert.equal(status(result, "registry-inception"), "failed");
    assert.equal(status(result, "issuance"), "failed");
    assert.equal(status(result, "issuance-anchor"), "skipped");
  });

  test("should not throw on tampered input", async () => {
    const tampered = await fixtureIndex((body) => {
      (body.a as Record<string, unknown>).LEI = "999999999";
      return body;
    });
    const bare = new EventIndex(
      (await fixtureMessages("credential.cesr")).filter((m) => m.version.protocol === "ACDC"),
    );

    assert.doesNotThrow(() => verifyCredential(tampered, CREDENTIAL));
    assert.doesNotThrow(() => verifyCredential(bare, CREDENTIAL));
  });

  test("should report a revoked credential as authentic but revoked", () => {
    const issuer = newIssuer();
    const { credential, iss } = issuer.issue();
    issuer.revoke(credential, iss);

    const result = verifyCredential(new EventIndex(issuer.messages), credential.body.d);

    assert.equal(status(result, "revocation-anchor"), "passed");
    assert.equal(result.status, "revoked");
    assert.equal(result.ok, true);
    assert.ok(result.revokedAt);
  });

  test("should fail the revocation when it chains to the wrong issuance", () => {
    const issuer = newIssuer();
    const { credential, iss } = issuer.issue();
    const rev = issuer.revoke(credential, iss);

    const messages = issuer.messages.map((message) =>
      message.body.d === rev.body.d ? new Message({ ...rev.body, p: iss.body.i }, message.attachments) : message,
    );
    const result = verifyCredential(new EventIndex(messages), credential.body.d);

    assert.equal(status(result, "revocation-anchor"), "failed");
    assert.equal(result.status, "revoked");
    assert.equal(result.ok, false);
  });

  describe("edges", () => {
    test("should resolve a chained credential against the same index", () => {
      const issuer = newIssuer();
      const { credential: qvi } = issuer.issue({ schema: SCHEMA });
      const { credential: le } = issuer.issue({
        schema: OTHER_SCHEMA,
        edges: { qvi: { n: qvi.body.d, s: SCHEMA } },
      });

      const results = verifyCredentials(new EventIndex(issuer.messages));
      const byId = new Map(results.map((r) => [r.said, r]));

      assert.equal(results.length, 2);
      assert.equal(byId.get(qvi.body.d)?.ok, true);
      assert.equal(status(byId.get(qvi.body.d) as CredentialVerification, "edges"), "not-applicable");

      const leResult = byId.get(le.body.d) as CredentialVerification;
      assert.equal(leResult.ok, true);
      assert.equal(status(leResult, "edges"), "passed");
      assert.deepEqual(leResult.edges, [{ label: "qvi", said: qvi.body.d, ok: true }]);
    });

    test("should fail when an edge references a credential outside the index", () => {
      const issuer = newIssuer();
      const { credential: qvi } = issuer.issue();
      const { credential: le } = issuer.issue({ edges: { qvi: { n: qvi.body.d } } });

      // Drop the referenced credential from the stream.
      const messages = issuer.messages.filter((message) => message.body.d !== qvi.body.d);
      const result = verifyCredential(new EventIndex(messages), le.body.d);

      assert.equal(result.ok, false);
      assert.equal(status(result, "edges"), "failed");
      assert.match(detail(result, "edges"), /not in the stream/);
      assert.deepEqual(result.edges, [{ label: "qvi", said: qvi.body.d, ok: false }]);
    });

    test("should fail when an edge declares a different schema than the credential it names", () => {
      const issuer = newIssuer();
      const { credential: qvi } = issuer.issue({ schema: SCHEMA });
      const { credential: le } = issuer.issue({ edges: { qvi: { n: qvi.body.d, s: OTHER_SCHEMA } } });

      const result = verifyCredential(new EventIndex(issuer.messages), le.body.d);

      assert.equal(status(result, "edges"), "failed");
      assert.match(detail(result, "edges"), /declares schema/);
    });

    test("should fail when an edge references a revoked credential", () => {
      const issuer = newIssuer();
      const { credential: qvi, iss } = issuer.issue();
      const { credential: le } = issuer.issue({ edges: { qvi: { n: qvi.body.d } } });
      issuer.revoke(qvi, iss);

      const result = verifyCredential(new EventIndex(issuer.messages), le.body.d);

      assert.equal(status(result, "edges"), "failed");
      assert.match(detail(result, "edges"), /revoked/);
    });

    test("should fail when an edge references a credential that does not verify", () => {
      const issuer = newIssuer();
      const { credential: qvi } = issuer.issue();
      const { credential: le } = issuer.issue({ edges: { qvi: { n: qvi.body.d } } });

      // Break the referenced credential without changing the SAID it is indexed by.
      const messages = issuer.messages.map((message) =>
        message.body.d === qvi.body.d
          ? new Message({ ...(message.body as CredentialBody), ri: "EOtherRegistry" }, message.attachments)
          : message,
      );
      const result = verifyCredential(new EventIndex(messages), le.body.d);

      assert.equal(status(result, "edges"), "failed");
      assert.match(detail(result, "edges"), /did not verify/);
    });

    // Real SAIDs cannot form a cycle, but hand-crafted input can; this proves the
    // walk terminates rather than recursing forever.
    test("should fail rather than recurse when edges form a cycle", () => {
      const issuer = newIssuer();
      const { credential: first } = issuer.issue();
      const { credential: second } = issuer.issue({ edges: { back: { n: first.body.d } } });

      const messages = issuer.messages.map((message) =>
        message.body.d === first.body.d
          ? new Message(
              { ...(message.body as CredentialBody), e: { d: "x", fwd: { n: second.body.d } } },
              message.attachments,
            )
          : message,
      );
      const result = verifyCredential(new EventIndex(messages), second.body.d);

      assert.equal(status(result, "edges"), "failed");
      assert.match(detail(result, "edges"), /did not verify|cycle/);
    });
  });
});
