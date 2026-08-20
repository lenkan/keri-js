import assert from "node:assert";
import test, { after, before } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { KERIPy } from "../test_utils/keripy.ts";
import { type Endpoint, startKerijsVerifier } from "./utils.ts";

let verifier: Endpoint;
const abortController = new AbortController();

before(async () => {
  verifier = await startKerijsVerifier({ signal: abortController.signal });
});

after(() => {
  abortController.abort();
});

interface LoginStatus {
  phase: string;
  aid?: string;
  words?: string[];
  error?: string;
  identity?: { aid: string; sequenceNumber: number; signingKeys: string[]; witnesses: string[] };
}

async function mintSession(): Promise<string> {
  const response = await fetch(`${verifier.url}/api/login/sessions`, { method: "POST" });
  assert.equal(response.status, 200);
  const { token } = (await response.json()) as { token: string };
  return token;
}

async function submitKel(token: string, kel: string): Promise<{ status: number; aid?: string; words?: string[] }> {
  const response = await fetch(`${verifier.url}/api/login/sessions/${token}/kel`, { method: "POST", body: kel });
  if (!response.ok) {
    return { status: response.status };
  }
  const body = (await response.json()) as { aid: string; words: string[] };
  return { status: response.status, ...body };
}

async function readStatus(token: string): Promise<LoginStatus | null> {
  const response = await fetch(`${verifier.url}/api/login/sessions/${token}`);
  if (response.status === 204) {
    return null;
  }
  return (await response.json()) as LoginStatus;
}

async function waitFor(token: string, check: (status: LoginStatus | null) => boolean): Promise<LoginStatus | null> {
  let status: LoginStatus | null = null;
  for (let attempt = 0; attempt < 20; attempt++) {
    status = await readStatus(token);
    if (check(status)) {
      return status;
    }
    await delay(500);
  }
  return status;
}

test("KERIpy controller logs in with a pushed KEL and a challenge response", async () => {
  const keripy = new KERIPy();

  await keripy.init();
  await keripy.incept({ toad: 0 });
  const aid = await keripy.aid();

  const token = await mintSession();

  const submitted = await submitKel(token, await keripy.export());
  assert.equal(submitted.status, 200);
  assert.equal(submitted.aid, aid);
  assert.equal(submitted.words?.length, 12);

  await keripy.oobi.resolve(verifier.oobi, "portal");
  await keripy.challenge.respond({ words: submitted.words ?? [], recipient: "portal" });

  const status = await waitFor(token, (s) => s?.phase === "authenticated");
  assert.equal(status?.phase, "authenticated");
  assert.equal(status?.identity?.aid, aid);
  assert.equal(status?.identity?.sequenceNumber, 0);
  assert.deepEqual(status?.identity?.witnesses, []);
});

test("a rotation between challenge and response surfaces as a retryable error", async () => {
  const keripy = new KERIPy();

  await keripy.init();
  await keripy.incept({ toad: 0 });
  const aid = await keripy.aid();

  const token = await mintSession();
  const first = await submitKel(token, await keripy.export());
  assert.equal(first.status, 200);

  // Rotate after the challenge was issued: KERIpy seals the response to the
  // rotation, which the portal has never seen.
  await keripy.rotate();
  await keripy.oobi.resolve(verifier.oobi, "portal");
  await keripy.challenge.respond({ words: first.words ?? [], recipient: "portal" });

  const stale = await waitFor(token, (s) => Boolean(s?.phase === "challenged" && s.error));
  assert.equal(stale?.phase, "challenged");
  assert.match(stale?.error ?? "", /out of date/);

  // Recovery: re-export the rotated KEL (a clean extension of the stored
  // history, not duplicity) and answer the fresh challenge.
  const second = await submitKel(token, await keripy.export());
  assert.equal(second.status, 200);
  assert.notDeepEqual(second.words, first.words);

  await keripy.challenge.respond({ words: second.words ?? [], recipient: "portal" });

  const status = await waitFor(token, (s) => s?.phase === "authenticated");
  assert.equal(status?.phase, "authenticated");
  assert.equal(status?.identity?.aid, aid);
  assert.equal(status?.identity?.sequenceNumber, 1);
});
