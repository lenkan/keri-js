import assert from "node:assert";
import test from "node:test";
import { EventIndex, verifyCredentials } from "keri";
import { KERIPy } from "../test_utils/keripy.ts";
import { startKerijsVerifier } from "./utils.ts";

const SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const REGISTRY_NAME = "presentation-registry";

interface Session {
  token: string;
  aid: string;
  oobi: string;
}

async function collect(url: string, token: string): Promise<string> {
  // `kli` delivers before it exits, so this is a guard against scheduling
  // rather than a wait for a mailbox round trip.
  for (let attempt = 0; attempt < 10; attempt++) {
    const response = await fetch(`${url}/api/sessions/${token}`);

    if (response.status === 200) {
      return response.text();
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error("Verifier never received the presentation");
}

test("KERIpy presents a credential to a KERIjs verifier over IPEX", async () => {
  const abort = new AbortController();

  try {
    const verifier = await startKerijsVerifier({ signal: abort.signal });

    // No witness and no mailbox on either side: the verifier claims the
    // `controller` end role, so `kli` posts the grant straight to it.
    const keripy = new KERIPy();
    await keripy.init();
    await keripy.oobi.resolve(`https://weboftrust.github.io/oobi/${SCHEMA_SAID}`);
    await keripy.incept({ toad: 0 });

    const issuer = await keripy.aid();

    await keripy.registry.incept({ registryName: REGISTRY_NAME });
    await keripy.vc.create({
      registryName: REGISTRY_NAME,
      schema: SCHEMA_SAID,
      recipient: issuer,
      data: { LEI: "1234567890123456789" },
    });

    const said = (await keripy.vc.list({ said: true, issued: true }))
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .at(-1);

    assert.ok(said, "Expected a credential SAID after issuance");

    const response = await fetch(`${verifier.url}/api/sessions`, { method: "POST" });
    const session = (await response.json()) as Session;

    assert.strictEqual(session.aid, verifier.aid);

    await keripy.oobi.resolve(verifier.oobi, "verifier");
    await keripy.ipex.grant({ said, recipient: verifier.aid, message: session.token });

    const cesr = await collect(verifier.url, session.token);

    // The browser verifies exactly this stream, so assert on it the same way.
    const results = verifyCredentials(await EventIndex.parse(cesr));
    assert.strictEqual(results.length, 1);

    const result = results[0];
    assert.strictEqual(result.credential.body.d, said);
    assert.strictEqual(result.credential.body.i, issuer);

    // `kli ipex grant` ships the issuer KEL and registry events alongside the
    // grant, so everything but the offline-only schema check must resolve.
    const unresolved = result.checks.filter((check) => check.status === "failed" || check.status === "skipped");
    assert.deepStrictEqual(unresolved, [], `Unresolved checks: ${JSON.stringify(unresolved)}`);

    const byId = Object.fromEntries(result.checks.map((check) => [check.id, check.status]));
    assert.strictEqual(byId["issuer-kel"], "passed");
    assert.strictEqual(byId["registry-anchor"], "passed");
    assert.strictEqual(byId["issuance-anchor"], "passed");
  } finally {
    abort.abort();
  }
});
