import assert from "node:assert";
import test, { after, before } from "node:test";
import { KERIPy } from "./keripy.ts";
import { createController, startKeripyWitness, type Witness } from "./utils.ts";

const SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

let wan: Witness;
let wil: Witness;
const abortController = new AbortController();

before(async () => {
  wan = await startKeripyWitness({ signal: abortController.signal });
  wil = await startKeripyWitness({ signal: abortController.signal });
});

after(() => {
  abortController.abort();
});

test("KERIpy issues credential to KERIjs via IPEX", async () => {
  const keripy = new KERIPy();

  // Set up KERIpy identity on wil (issuer)
  await keripy.init();
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${SCHEMA_SAID}`);
  await keripy.oobi.resolve(wil.oobi, "wil");
  await keripy.incept({ wits: [wil.aid], toad: 1 });
  await keripy.ends.add({ eid: wil.aid });

  const keripy_aid = await keripy.aid();

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
  const keripy_oobi = `${wil.url}/oobi/${keripy_aid}`;
  const kerijs_oobi = `${wan.url}/oobi/${jsState.id}/mailbox`;

  await controller.introduce(keripy_oobi);
  await keripy.oobi.resolve(kerijs_oobi, "kerijs");

  // KERIpy creates registry and issues credential to KERIjs
  const REGISTRY_NAME = "test-registry";
  await keripy.registry.incept({ registryName: REGISTRY_NAME });

  await keripy.vc.create({
    registryName: REGISTRY_NAME,
    schema: SCHEMA_SAID,
    recipient: jsState.id,
    data: { LEI: "12312312312312321" },
  });

  // Get the credential SAID from keripy's issued credentials
  const credSaid = (await keripy.vc.list({ said: true, issued: true }))
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .at(-1);

  assert.ok(credSaid, "Expected credential SAID after issuance");

  // KERIpy grants credential to KERIjs
  await keripy.ipex.grant({ said: credSaid, recipient: jsState.id });

  // KeriJS queries its mailbox and receives the grant (retry until delivered)
  let credentials: Awaited<ReturnType<typeof controller.receiveGrants>> = [];
  for (let attempt = 0; attempt < 10 && credentials.length === 0; attempt++) {
    if (attempt > 0) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }

    credentials = await controller.receiveGrants(jsState.id);
  }

  assert.ok(credentials.length > 0, "Expected at least one credential to be received");
  assert.strictEqual(credentials[0].s, SCHEMA_SAID, "Credential schema should match");

  // Verify credential is persisted in KeriJS storage
  const stored = await controller.getCredential(credentials[0].d);
  assert.ok(stored, "Expected credential to be retrievable from storage");
});
