import assert from "node:assert";
import { resolveWitness, createController } from "../test_integration/utils.ts";
import { KERIPy } from "./keripy.ts";

const SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

const wan = await resolveWitness("http://localhost:5642");
const wil = await resolveWitness("http://localhost:5643");

const keripy = new KERIPy();

// Set up KERIpy identity on wil (issuer)
keripy.init();
keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${SCHEMA_SAID}`);
keripy.oobi.resolve(`http://localhost:5643/oobi`, "wil");
keripy.incept({ wits: [wil.aid], toad: 1 });
keripy.ends.add({ eid: wil.aid });

const keripy_aid = keripy.aid();

// Set up KeriJS identity on wan (holder)
const controller = createController();
await controller.introduce(wan.oobi);

const jsState = await controller.incept({ wits: [wan.aid], toad: 1 });

await controller.reply({
  id: jsState.id,
  route: "/end/role/add",
  record: { cid: jsState.id, eid: wan.aid, role: "mailbox" },
});

// Cross-resolve OOBIs
const keripy_oobi = `http://localhost:5643/oobi/${keripy_aid}`;
const kerijs_oobi = `http://localhost:5642/oobi/${jsState.id}/mailbox`;

await controller.introduce(keripy_oobi);
keripy.oobi.resolve(kerijs_oobi, "kerijs");

// KERIpy creates registry and issues credential to KeriJS
const REGISTRY_NAME = "test-registry";
keripy.registry.incept({ registryName: REGISTRY_NAME });

keripy.vc.create({
  registryName: REGISTRY_NAME,
  schema: SCHEMA_SAID,
  recipient: jsState.id,
  data: { LEI: "12312312312312321" },
});

// Get the credential SAID from keripy's issued credentials
const credSaid = keripy.vc
  .list({ said: true, issued: true })
  .split("\n")
  .filter((l) => l.trim().length > 0)
  .at(-1);

assert.ok(credSaid, "Expected credential SAID after issuance");

// KERIpy grants credential to KeriJS
keripy.ipex.grant({ said: credSaid, recipient: jsState.id });

// KeriJS queries its mailbox and receives the grant (retry until delivered)
let credentials: Awaited<ReturnType<typeof controller.receiveGrants>> = [];
for (let attempt = 0; attempt < 10 && credentials.length === 0; attempt++) {
  if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 2000));

  credentials = await controller.receiveGrants(jsState.id);
}

assert.ok(credentials.length > 0, "Expected at least one credential to be received");
assert.strictEqual(credentials[0].s, SCHEMA_SAID, "Credential schema should match");

// Verify credential is persisted in KeriJS storage
const stored = await controller.getCredential(credentials[0].d);
assert.ok(stored, "Expected credential to be retrievable from storage");
