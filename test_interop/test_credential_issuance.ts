import assert from "node:assert";
import test, { after, before } from "node:test";
import { KERIPy } from "./keripy.ts";
import { createController, type Endpoint, startKeripyWitness } from "./utils.ts";

const QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";
const ECR_SCHEMA = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw";

const RULES = {
  usageDisclaimer: {
    l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
  },
  issuanceDisclaimer: {
    l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
  },
};

let wan: Endpoint;
let wil: Endpoint;
const abortController = new AbortController();

before(async () => {
  wan = await startKeripyWitness({ signal: abortController.signal });
  wil = await startKeripyWitness({ signal: abortController.signal });
});

after(() => {
  abortController.abort();
});

test("KERIjs issues credential to KERIpy via IPEX", async () => {
  const keripy = new KERIPy();

  // Set up KERIpy identity on wil
  await keripy.init();
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${QVI_SCHEMA}`);
  await keripy.oobi.resolve(wil.oobi, "wil");
  await keripy.incept({ wits: [wil.aid], toad: 1 });
  await keripy.ends.add({ eid: wil.aid });

  const keripy_aid = await keripy.aid();

  // Set up KeriJS identity on wan
  const controller = createController();
  await controller.introduce(wan.oobi);

  const jsState = await controller.incept({ wits: [wan.aid], toad: 1 });

  await controller.reply({
    id: jsState.id,
    route: "/end/role/add",
    record: { cid: jsState.id, eid: wan.aid, role: "mailbox" },
  });

  // Cross-resolve OOBIs
  const keripy_oobi = `${wil.url}/oobi/${keripy_aid}`;
  const kerijs_oobi = `${wan.url}/oobi/${jsState.id}`;

  await controller.introduce(keripy_oobi);
  await keripy.oobi.resolve(kerijs_oobi, "kerijs");

  // KeriJS creates registry and credential
  const registry = await controller.createRegistry(jsState.id);

  const credential = await controller.createCredential({
    registryId: registry.i,
    schemaId: QVI_SCHEMA,
    holder: keripy_aid,
    data: { LEI: "12312312312312321" },
    rules: RULES,
  });

  await controller.issueCredential(credential);
  await controller.sendCredentialArtifacts(credential, keripy_aid);
  await controller.grant({ credential });

  // KERIpy polls and admits the grant
  await keripy.query({ prefix: jsState.id });
  await keripy.ipex.list({ type: "grant", poll: true });

  const grants = await keripy.ipex.list({ type: "grant", said: true });
  assert.ok(grants.length > 0, "Expected at least one grant");

  const grantSaid = grants[grants.length - 1];
  assert(grantSaid);
  await keripy.ipex.admit(grantSaid);

  const vcOutput = await keripy.vc.list();
  assert.ok(vcOutput.trim().length > 0, "Expected vc list to contain at least one credential");
});

test("KERIjs issues chained vLEI credentials to KERIpy via IPEX", async () => {
  const keripy = new KERIPy();

  // Set up KERIpy identity on wil
  await keripy.init();
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${QVI_SCHEMA}`);
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${LE_SCHEMA}`);
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${ECR_SCHEMA}`);
  await keripy.oobi.resolve(wil.oobi, "wil");
  await keripy.incept({ wits: [wil.aid], toad: 1 });
  await keripy.ends.add({ eid: wil.aid });

  const keripy_aid = await keripy.aid();

  // Set up KeriJS identity on wan
  const controller = createController();
  await controller.introduce(wan.oobi);

  const jsState = await controller.incept({ wits: [wan.aid], toad: 1 });

  await controller.reply({
    id: jsState.id,
    route: "/end/role/add",
    record: { cid: jsState.id, eid: wan.aid, role: "mailbox" },
  });

  // Cross-resolve OOBIs
  const keripy_oobi = `${wil.url}/oobi/${keripy_aid}`;
  const kerijs_oobi = `${wan.url}/oobi/${jsState.id}/witness`;

  await controller.introduce(keripy_oobi);
  await keripy.oobi.resolve(kerijs_oobi, "kerijs");

  // Create registry
  const registry = await controller.createRegistry(jsState.id);

  // QVI credential (issued to self)
  const qviCredential = await controller.createCredential({
    registryId: registry.i,
    schemaId: QVI_SCHEMA,
    holder: jsState.id,
    data: { LEI: "12312312312312321" },
    rules: RULES,
  });
  await controller.issueCredential(qviCredential);

  // LE credential (issued to self, edges → QVI)
  const leCredential = await controller.createCredential({
    registryId: registry.i,
    schemaId: LE_SCHEMA,
    holder: jsState.id,
    data: { LEI: "12312312312312321" },
    rules: RULES,
    edges: { qvi: { n: qviCredential.d, s: QVI_SCHEMA } },
  });
  await controller.issueCredential(leCredential);

  // ECR credential (issued to keripy, edges → LE)
  const ecrCredential = await controller.createCredential({
    registryId: registry.i,
    schemaId: ECR_SCHEMA,
    holder: keripy_aid,
    salt: "0ACnKiVvJ-_R-C36cQhpIgTw",
    data: { LEI: "12312312312312321", personLegalName: "John Doe", engagementContextRole: "Test Driver" },
    rules: {
      ...RULES,
      privacyDisclaimer: {
        l: "It is the sole responsibility of Holders as Issuees of an ECR vLEI Credential to present that Credential in a privacy-preserving manner using the mechanisms provided in the Issuance and Presentation Exchange (IPEX) protocol specification and the Authentic Chained Data Container (ACDC) specification. https://github.com/WebOfTrust/IETF-IPEX and https://github.com/trustoverip/tswg-acdc-specification.",
      },
    },
    edges: { le: { n: leCredential.d, s: LE_SCHEMA } },
  });
  await controller.issueCredential(ecrCredential);
  await controller.sendCredentialArtifacts(ecrCredential, keripy_aid);
  await controller.grant({ credential: ecrCredential });

  // KERIpy polls and admits the grant
  await keripy.query({ prefix: jsState.id });
  await keripy.ipex.list({ type: "grant", poll: true });

  const grants = await keripy.ipex.list({ type: "grant", said: true });
  assert.ok(grants.length > 0, "Expected at least one grant");

  const grantSaid = grants[grants.length - 1];
  assert(grantSaid);
  await keripy.ipex.admit(grantSaid);

  const vcOutput = await keripy.vc.list();
  assert.ok(vcOutput.trim().length > 0, "Expected vc list to contain at least one credential");
});

test("KERIjs issues credential to KERIpy without witness mailbox", async () => {
  const keripy = new KERIPy();

  // Set up KERIpy identity on wan
  await keripy.init();
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${QVI_SCHEMA}`);
  await keripy.oobi.resolve(wan.oobi, "wan");
  await keripy.incept({ wits: [wan.aid], toad: 1 });
  await keripy.ends.add({ eid: wan.aid });

  const keripy_aid = await keripy.aid();

  // Set up KeriJS identity without a witness
  const controller = createController();
  const jsState = await controller.incept({});

  // KeriJS resolves KERIpy OOBI through wan
  const keripy_oobi = `${wan.url}/oobi/${keripy_aid}`;
  await controller.introduce(keripy_oobi);

  // KeriJS creates registry and credential
  const registry = await controller.createRegistry(jsState.id);

  const credential = await controller.createCredential({
    registryId: registry.i,
    schemaId: QVI_SCHEMA,
    holder: keripy_aid,
    data: { LEI: "12312312312312321" },
    rules: RULES,
  });

  await controller.issueCredential(credential);
  await controller.sendCredentialArtifacts(credential, keripy_aid);
  await controller.grant({ credential });

  // KERIpy polls and admits the grant
  await keripy.ipex.list({ type: "grant", poll: true });

  const grants = await keripy.ipex.list({ type: "grant", said: true });
  assert.ok(grants.length > 0, "Expected at least one grant");

  const grantSaid = grants[grants.length - 1];
  assert(grantSaid);
  await keripy.ipex.admit(grantSaid);

  const vcOutput = await keripy.vc.list();
  assert.ok(vcOutput.trim().length > 0, "Expected vc list to contain at least one credential");
});

test("KERIjs issues chained credentials to KERIpy without witness mailbox", async () => {
  const keripy = new KERIPy();

  // Set up KERIpy identity on wan
  await keripy.init();
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${QVI_SCHEMA}`);
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${LE_SCHEMA}`);
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${ECR_SCHEMA}`);
  await keripy.oobi.resolve(wan.oobi, "wan");
  await keripy.incept({ wits: [wan.aid], toad: 1 });
  await keripy.ends.add({ eid: wan.aid });

  const keripy_aid = await keripy.aid();

  // Set up KeriJS identity without a witness
  const controller = createController();
  const jsState = await controller.incept({});

  // KeriJS resolves KERIpy OOBI through wan
  const keripy_oobi = `${wan.url}/oobi/${keripy_aid}`;
  await controller.introduce(keripy_oobi);

  // Create registry
  const registry = await controller.createRegistry(jsState.id);

  // QVI credential (issued to self)
  const qviCredential = await controller.createCredential({
    registryId: registry.i,
    schemaId: QVI_SCHEMA,
    holder: jsState.id,
    data: { LEI: "12312312312312321" },
    rules: RULES,
  });
  await controller.issueCredential(qviCredential);

  // LE credential (issued to self, edges → QVI)
  const leCredential = await controller.createCredential({
    registryId: registry.i,
    schemaId: LE_SCHEMA,
    holder: jsState.id,
    data: { LEI: "12312312312312321" },
    rules: RULES,
    edges: { qvi: { n: qviCredential.d, s: QVI_SCHEMA } },
  });
  await controller.issueCredential(leCredential);

  // ECR credential (issued to keripy, edges → LE)
  const ecrCredential = await controller.createCredential({
    registryId: registry.i,
    schemaId: ECR_SCHEMA,
    holder: keripy_aid,
    salt: "0ACnKiVvJ-_R-C36cQhpIgTw",
    data: { LEI: "12312312312312321", personLegalName: "John Doe", engagementContextRole: "Test Driver" },
    rules: {
      ...RULES,
      privacyDisclaimer: {
        l: "It is the sole responsibility of Holders as Issuees of an ECR vLEI Credential to present that Credential in a privacy-preserving manner using the mechanisms provided in the Issuance and Presentation Exchange (IPEX) protocol specification and the Authentic Chained Data Container (ACDC) specification. https://github.com/WebOfTrust/IETF-IPEX and https://github.com/trustoverip/tswg-acdc-specification.",
      },
    },
    edges: { le: { n: leCredential.d, s: LE_SCHEMA } },
  });
  await controller.issueCredential(ecrCredential);
  await controller.sendCredentialArtifacts(ecrCredential, keripy_aid);
  await controller.grant({ credential: ecrCredential });

  // KERIpy polls and admits the grant
  await keripy.ipex.list({ type: "grant", poll: true });

  const grants = await keripy.ipex.list({ type: "grant", said: true });
  assert.ok(grants.length > 0, "Expected at least one grant");

  const grantSaid = grants[grants.length - 1];
  assert(grantSaid);
  await keripy.ipex.admit(grantSaid);

  const vcOutput = await keripy.vc.list();
  assert.ok(vcOutput.trim().length > 0, "Expected vc list to contain at least one credential");
});
