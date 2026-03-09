import test, { beforeEach, describe, mock } from "node:test";
import assert from "node:assert";
import { Attachments, cesr } from "cesr";
import { Controller, type InceptResult } from "./controller.ts";
import { blake3 } from "@noble/hashes/blake3.js";
import { keri, type LocationRecord, type EndRoleRecord } from "#keri/core";
import { DatabaseSync } from "node:sqlite";
import { SqliteControllerStorage } from "#keri/sqlite-storage";

const fetch = mock.method(globalThis, "fetch", () => {
  return Response.json({});
});

function createController() {
  return new Controller({
    storage: new SqliteControllerStorage(new DatabaseSync(":memory:")),
  });
}

describe("incept", () => {
  test("should create inception event", async () => {
    const controller = createController();

    const result = await controller.incept();

    assert.strictEqual(result.event.t, "icp");
    assert.strictEqual(result.event.s, "0");
  });
});

describe("interact", () => {
  let controller: Controller;
  let icp: InceptResult;

  beforeEach(async () => {
    controller = createController();
    icp = await controller.incept();
  });

  test("should create interaction event", async () => {
    const data = { test: "data" };
    const ixn = await controller.anchor(icp.id, { data });

    assert.strictEqual(ixn.event.t, "ixn");
    assert.strictEqual(ixn.event.s, "1", "Sequence number");
    assert.strictEqual(ixn.event.p, icp.event.d, "Prior event digest");
    assert.deepStrictEqual(ixn.event.a, [data], "Anchor data");
  });

  test("should create multiple interaction events", async () => {
    const data1 = { test: "data1" };
    const data2 = { test: "data2" };

    const ixn1 = await controller.anchor(icp.id, { data: data1 });
    const ixn2 = await controller.anchor(icp.id, { data: data2 });

    assert.strictEqual(ixn1.event.t, "ixn");
    assert.strictEqual(ixn1.event.s, "1", "Sequence number of first interaction event");
    assert.strictEqual(ixn1.event.p, icp.event.d, "Prior event digest of first interaction event");
    assert.deepStrictEqual(ixn1.event.a, [data1], "Anchor data of first interaction event");

    assert.strictEqual(ixn2.event.t, "ixn");
    assert.strictEqual(ixn2.event.s, "2", "Sequence number of second interaction event");
    assert.strictEqual(ixn2.event.p, ixn1.event.d, "Prior event digest of second interaction event");
    assert.deepStrictEqual(ixn2.event.a, [data2], "Anchor data of second interaction event");
  });

  test("should throw if state is not found", async () => {
    await assert.rejects(() => controller.anchor("nonexistent", { data: {} }), {
      message: "State for id nonexistent not found",
    });
  });
});

describe("rotate", () => {
  let controller: Controller;
  let icp: InceptResult;

  beforeEach(async () => {
    controller = new Controller({ storage: new SqliteControllerStorage(new DatabaseSync(":memory:")) });
    icp = await controller.incept();
  });

  test("create rotation event", async () => {
    const data = { test: "data" };
    const rot = await controller.rotate(icp.id, { data });

    assert.strictEqual(rot.event.t, "rot");
    assert.strictEqual(rot.event.s, "1", "Sequence number");
    assert.strictEqual(rot.event.p, icp.event.d, "Prior event digest");
    assert.deepStrictEqual(rot.event.a, [data], "Anchor data");
  });

  test("rotate after interaction", async () => {
    const ixn = await controller.anchor(icp.id, { data: { test: "data" } });
    const rot = await controller.rotate(icp.id, {});

    assert.strictEqual(rot.event.t, "rot");
    assert.strictEqual(rot.event.s, "2", "Sequence number");
    assert.strictEqual(rot.event.p, ixn.event.d, "Prior event digest");
  });

  test("set key to pre-committed next key", async () => {
    const rot = await controller.rotate(icp.id, {});

    const keydigest = cesr.crypto
      .blake3_256(blake3.create().update(new TextEncoder().encode(rot.event.k[0])).digest())
      .text();

    assert.strictEqual(
      keydigest,
      icp.event.n[0],
      "Rotation event key digest should match pre-committed next key digest",
    );
  });
});

describe("registry", () => {
  test("should list registries by owner", async () => {
    const controller = createController();

    const owner1 = await controller.incept();
    const owner2 = await controller.incept();

    const registry1 = await controller.createRegistry(owner1.id);
    const registry2 = await controller.createRegistry(owner1.id);
    await controller.createRegistry(owner2.id);

    const registries = await controller.listRegistries(owner1.id);

    assert.strictEqual(registries.length, 2);
    assert.strictEqual(registries[0].ii, owner1.id);
    assert.strictEqual(registries[1].ii, owner1.id);
    assert.strictEqual(registries[0].d, registry1.d);
    assert.strictEqual(registries[1].d, registry2.d);
  });
});

describe("credential", () => {
  test("should create and persist credential data", async () => {
    const controller = createController();
    const owner = await controller.incept();
    const registry = await controller.createRegistry(owner.id);

    const credential = await controller.createCredential({
      registryId: registry.i,
      schemaId: "ESchema",
      holder: "EHolder",
      data: {
        lei: "5493001KJTIIGC8Y1R12",
      },
      rules: {
        usageDisclaimer: {
          l: "Usage disclaimer",
        },
      },
    });

    const stored = await controller.getCredential(credential.d);
    const listed = await controller.listCredentials(registry.i);

    assert.ok(stored);
    assert.strictEqual(stored?.d, credential.d);
    assert.strictEqual(listed.length, 1);
    assert.strictEqual(listed[0].d, credential.d);
  });
});

describe("forward", () => {
  beforeEach(() => {
    fetch.mock.resetCalls();
  });

  test("Forward exchange event", async () => {
    const controller = createController();
    const timestamp = keri.utils.formatDate(new Date(Date.parse("2023-10-01T00:00:00Z")));

    const mailbox = await controller.incept();
    await controller.reply({
      id: mailbox.id,
      route: "/loc/scheme",
      record: {
        scheme: "http",
        url: "http://example.com/mailbox",
        eid: mailbox.id,
      },
    });

    const recipient = await controller.incept();
    await controller.reply({
      id: recipient.id,
      route: "/end/role/add",
      record: {
        role: "mailbox",
        cid: recipient.id,
        eid: mailbox.id,
      },
    });

    const icp = await controller.incept();

    const exn = keri.exchange({
      timestamp: timestamp,
      sender: icp.event.i,
      route: "/challenge/response",
    });

    await controller.forward({
      sender: icp.id,
      topic: "challenge",
      recipient: recipient.id,
      timestamp: timestamp,
      message: exn,
    });

    const headers = new Headers(fetch.mock.calls[0].arguments[1]?.headers ?? {});
    const attachments = Attachments.parse(new TextEncoder().encode(headers.get("CESR-ATTACHMENT") ?? ""));

    assert(attachments);
    const frames = attachments.frames().map((frame) => frame.text());
    assert.strictEqual(frames[0], "-VBs");
    assert.strictEqual(frames[1], "-FAB");
    assert.strictEqual(frames[2], icp.id);
    assert.strictEqual(frames[3], "0AAAAAAAAAAAAAAAAAAAAAAA");
    assert.strictEqual(frames[4], icp.id);
    assert.strictEqual(frames[5], "-AAB");
    assert.strictEqual(frames[6].substring(0, 2), "AA");
    assert.strictEqual(frames[7], "-LA3");
    assert.strictEqual(frames[8], "5AACAA-e-evt");
    assert.strictEqual(frames[9], "-FAB");
    assert.strictEqual(frames[10], icp.id);
    assert.strictEqual(frames[11], "0AAAAAAAAAAAAAAAAAAAAAAA");
    assert.strictEqual(frames[12], icp.id);
    assert.strictEqual(frames[13], "-AAB");
    assert.strictEqual(frames[14].substring(0, 2), "AA");
  });
});

describe("grant", () => {
  beforeEach(() => {
    fetch.mock.resetCalls();
  });

  test("should forward ipex grant message", async () => {
    const controller = createController();

    const mailbox = await controller.incept();
    await controller.reply({
      id: mailbox.id,
      route: "/loc/scheme",
      record: {
        scheme: "http",
        url: "http://example.com/mailbox",
        eid: mailbox.id,
      },
    });

    const recipient = await controller.incept();
    await controller.reply({
      id: recipient.id,
      route: "/end/role/add",
      record: {
        role: "mailbox",
        cid: recipient.id,
        eid: mailbox.id,
      },
    });

    const issuer = await controller.incept();
    const registry = await controller.createRegistry(issuer.id);
    const credential = await controller.createCredential({
      registryId: registry.i,
      schemaId: "ESchema",
      holder: recipient.id,
      data: {
        LEI: "123123123123123",
      },
    });

    await controller.issueCredential(credential);
    await controller.grant({ credential });

    const [, request] = fetch.mock.calls.at(-1)?.arguments ?? [];
    const body = JSON.parse((request?.body as string) ?? "{}");

    assert.strictEqual(body.r, "/fwd");
    assert.strictEqual(body.q.pre, recipient.id);
    assert.strictEqual(body.q.topic, "credential");
    assert.strictEqual(body.e.evt.r, "/ipex/grant");
    assert.strictEqual(body.e.evt.e.acdc.d, credential.d);
  });

  test("should throw when issuance is missing", async () => {
    const controller = createController();
    const issuer = await controller.incept();
    const registry = await controller.createRegistry(issuer.id);
    const credential = await controller.createCredential({
      registryId: registry.i,
      schemaId: "ESchema",
      holder: issuer.id,
    });

    await assert.rejects(() => controller.grant({ credential }), {
      message: `No issuance found for said ${credential.d}`,
    });
  });
});

describe("credential", () => {
  test("Create credential", async () => {
    const controller = createController();
    const aid = await controller.incept();
    const registry = await controller.createRegistry(aid.id);
    const credential = await controller.createCredential({
      holder: aid.id,
      registryId: registry.i,
      schemaId: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      data: {
        LEI: "123123123123123",
      },
      rules: {
        usageDisclaimer: {
          l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
        },
        issuanceDisclaimer: {
          l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
        },
      },
    });

    assert.partialDeepStrictEqual(credential, {
      s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      i: aid.id,
      a: {
        LEI: "123123123123123",
      },
    });
  });

  test("Create and issue credential", async () => {
    const controller = createController();
    const aid = await controller.incept();
    const registry = await controller.createRegistry(aid.id);
    const credential = await controller.createCredential({
      holder: aid.id,
      registryId: registry.i,
      schemaId: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      data: {
        LEI: "123123123123123",
      },
      rules: {
        usageDisclaimer: {
          l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
        },
        issuanceDisclaimer: {
          l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
        },
      },
    });

    await controller.issueCredential(credential);

    assert.partialDeepStrictEqual(credential, {
      s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      i: aid.id,
      a: {
        LEI: "123123123123123",
      },
    });
  });

  test("Create chained credential", async () => {
    const controller = createController();
    const holder = await controller.incept();
    const issuer = await controller.incept();
    const registry = await controller.createRegistry(issuer.id);
    const LEI0 = "123123123123123";
    const LEI1 = "123123123123124";

    const credential0 = await controller.createCredential({
      holder: holder.id,
      registryId: registry.i,
      schemaId: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      data: {
        LEI: LEI0,
      },
      rules: {
        usageDisclaimer: {
          l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
        },
        issuanceDisclaimer: {
          l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
        },
      },
    });

    const credential1 = await controller.createCredential({
      holder: holder.id,
      registryId: registry.i,
      schemaId: "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
      data: {
        LEI: LEI1,
      },
      rules: {
        usageDisclaimer: {
          l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
        },
        issuanceDisclaimer: {
          l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
        },
      },
      edges: {
        qvi: {
          n: credential0.d,
          s: credential0.s,
        },
      },
    });

    assert.partialDeepStrictEqual(credential0, {
      s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
      i: issuer.id,
      a: {
        LEI: LEI0,
      },
      r: {},
    });

    assert.partialDeepStrictEqual(credential1, {
      s: "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
      i: issuer.id,
      a: {
        LEI: LEI1,
      },
      e: {
        qvi: {
          n: credential0.d,
          s: credential0.s,
        },
      },
    });
  });
});

describe("endpoint", () => {
  let storage: SqliteControllerStorage;
  let controller: Controller;

  beforeEach(() => {
    storage = new SqliteControllerStorage(new DatabaseSync(":memory:"));
    controller = new Controller({ storage });
  });

  function saveEndRole(record: EndRoleRecord) {
    storage.saveMessage(
      keri.reply({
        r: "/end/role/add",
        a: record,
      }),
    );
  }

  function saveLocation(record: LocationRecord) {
    storage.saveMessage(
      keri.reply({
        r: "/loc/scheme",
        a: record,
      }),
    );
  }

  test("resolves mailbox client", () => {
    const cid = "AID_CONTACT_1";
    const mailbox = "AID_MAILBOX_1";

    saveEndRole({ cid, role: "mailbox", eid: mailbox });
    saveLocation({ eid: mailbox, url: "http://localhost:5642", scheme: "http" });

    const endpoint = controller.resolveEndpoint(cid, "mailbox");

    assert.equal(endpoint.role, "mailbox");
  });

  test("throws when selected role has no location", () => {
    const cid = "AID_CONTACT_3";
    const agent = "AID_AGENT_3";
    const controllerAid = "AID_CONTROLLER_3";

    saveEndRole({ cid, role: "agent", eid: agent });
    saveEndRole({ cid, role: "controller", eid: controllerAid });
    saveLocation({ eid: agent, url: "http://localhost:5643", scheme: "http" });

    assert.throws(() => controller.resolveEndpoint(cid), {
      message: `No valid location found for aid ${cid}`,
    });
  });

  test("throws when no end role is found", () => {
    assert.throws(() => controller.resolveEndpoint("UNKNOWN_AID"), {
      message: "Could not find end role 'controller' for aid 'UNKNOWN_AID'",
    });
  });
});
