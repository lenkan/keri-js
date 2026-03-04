import assert from "node:assert";
import { resolveWitness, createController } from "../test_integration/utils.ts";
import { KERIPy } from "./keripy.ts";

const SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

const wan = await resolveWitness("http://localhost:5642");

const keripy = new KERIPy();

// Set up KERIpy identity on wan
keripy.init();
keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${SCHEMA_SAID}`);
keripy.oobi.resolve(`http://localhost:5642/oobi`, "wan");
keripy.incept({ wits: [wan.aid], toad: 1 });
keripy.ends.add({ eid: wan.aid });

const keripy_aid = keripy.aid();

// Set up KeriJS identity without a witness
const controller = createController();
const jsState = await controller.incept({});

// KeriJS resolves KERIpy OOBI through wan
const keripy_oobi = `http://localhost:5642/oobi/${keripy_aid}`;
await controller.introduce(keripy_oobi);

// KeriJS creates registry and credential
const registry = await controller.createRegistry(jsState.id);

const credential = await controller.createCredential({
  registryId: registry.i,
  schemaId: SCHEMA_SAID,
  holder: keripy_aid,
  data: { LEI: "12312312312312321" },
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
await controller.sendCredentialArtifacts(credential, keripy_aid);
await controller.grant({ credential });

// KERIpy polls and admits the grant
keripy.ipex.list({ type: "grant", poll: true });

const grants = keripy.ipex.list({ type: "grant", said: true });
assert.ok(grants.length > 0, "Expected at least one grant");

const grantSaid = grants[grants.length - 1];
assert(grantSaid);
keripy.ipex.admit(grantSaid);

const vcOutput = keripy.vc.list();
assert.ok(vcOutput.trim().length > 0, "Expected vc list to contain at least one credential");
