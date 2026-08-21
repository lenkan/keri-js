import assert from "node:assert";
import test, { after, before } from "node:test";
import { encodeText, type Message } from "cesr";
import { RoutedEvent } from "keri";
import { KERIPy } from "../test_utils/keripy.ts";
import { createController, type Endpoint, startKerijsPortal } from "./utils.ts";

const QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

const RULES = {
  usageDisclaimer: {
    l: "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.",
  },
  issuanceDisclaimer: {
    l: "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.",
  },
};

let portal: Endpoint;
const abortController = new AbortController();

before(async () => {
  portal = await startKerijsPortal({ signal: abortController.signal });
});

after(() => {
  abortController.abort();
});

function encode(messages: readonly Message[]): string {
  return messages
    .flatMap((message) => [new TextDecoder().decode(message.raw), encodeText(message.attachments.frames())])
    .join("");
}

/** The keri-js side of the `kli mailbox add` contract: POST the KEL and a signed end-role rpy. */
async function enrollController(
  controller: ReturnType<typeof createController>,
  id: string,
  signingKeys: string[],
): Promise<void> {
  const rpy = RoutedEvent.reply({
    r: "/end/role/add",
    a: { cid: id, role: "mailbox", eid: portal.aid },
  });

  const kel = await controller.export(id);
  const establishment = kel.at(0);
  assert(establishment);

  rpy.attachments = {
    TransIdxSigGroups: [
      {
        prefix: id,
        snu: establishment.body.s as string,
        digest: establishment.body.d as string,
        ControllerIdxSigs: await controller.sign(rpy.raw, signingKeys),
      },
    ],
  };

  const form = new FormData();
  form.set("kel", encode(kel));
  form.set("rpy", new TextDecoder().decode(rpy.raw) + encodeText(rpy.attachments.frames()));

  const response = await fetch(`${portal.url}/mailboxes`, { method: "POST", body: form });
  assert.equal(response.status, 200, await response.text());

  // The controller also ingests its own end-role, so it can resolve its own
  // mailbox when polling for responses.
  await controller.processMessage(rpy);
}

test("witness-less KERIpy receives and admits a credential through the portal", async () => {
  // Stock KERIpy enrolls with kli mailbox add: resolve the portal, then hand
  // it the KEL and the signed authorization in one command.
  const keripy = new KERIPy();
  await keripy.init();
  await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${QVI_SCHEMA}`);
  await keripy.incept({ toad: 0 });
  await keripy.oobi.resolve(portal.oobi, "portal");
  await keripy.mailbox.add({ mailbox: "portal" });

  const keripyAid = await keripy.aid();

  // The issuer lists the portal as its witness with toad 1: KERIpy refuses a
  // KEL with witnesses and toad 0, and `ipex admit` crashes outright on
  // issuers with no witnesses at all — so the portal receipts.
  const controller = createController();
  await controller.introduce(portal.oobi);
  const issuer = await controller.incept({ wits: [portal.aid], toad: 1 });
  await enrollController(controller, issuer.id, issuer.event.k);

  // Cross-introduction runs entirely through the portal's enrolled OOBIs —
  // no external witness serves anyone's KEL.
  await controller.introduce(`${portal.url}/oobi/${keripyAid}`);
  await keripy.oobi.resolve(`${portal.url}/oobi/${issuer.id}`, "kerijs");

  const registry = await controller.createRegistry(issuer.id);
  const credential = await controller.createCredential({
    registryId: registry.i,
    schemaId: QVI_SCHEMA,
    holder: keripyAid,
    data: { LEI: "12312312312312321" },
    rules: RULES,
  });

  await controller.issueCredential(credential);
  await controller.sendCredentialArtifacts(credential, keripyAid);
  await controller.grant({ credential });

  // The multi-message grant stream crossing the poll is the live regression
  // for the ordinal/inclusive cursor semantics.
  await keripy.ipex.list({ type: "grant", poll: true });
  const grants = await keripy.ipex.list({ type: "grant", said: true });
  assert.ok(grants.length > 0, "Expected at least one grant");

  const grantSaid = grants[grants.length - 1];
  assert(grantSaid);

  // Admit polls the portal for the TEL replay (`tels`/`logs` queries answered
  // into the /replay topic), verifies, and sends the admit exn back through
  // the portal to the issuer's mailbox.
  await keripy.ipex.admit(grantSaid);

  const vcOutput = await keripy.vc.list();
  assert.match(vcOutput, /Status:\s+Issued/, `Expected an issued credential, got:\n${vcOutput}`);

  // The admit exn arrived in the issuer's own mailbox on the portal.
  const received = await controller.query(issuer.id, "credential");
  const admits = received.filter((message) => (message.body as { r?: string }).r === "/ipex/admit");
  assert.ok(admits.length > 0, "Expected the admit exn in the issuer's mailbox");
});
