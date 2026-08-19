import assert from "node:assert";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { Attachments, encodeText, type Message, parse } from "cesr";
import type { ExchangeEventBody } from "keri";
import { EventIndex, embeds, IPEX_GRANT_ROUTE, keri } from "keri";
import { type SessionStore, Verifier } from "./verifier.ts";
import { createRouter } from "./verifier-router.ts";

const URL_BASE = "http://localhost:3002";

/** The mailbox-forwarded grant fixture, which nests /fwd around /ipex/grant. */
async function grantFixture(): Promise<Message<ExchangeEventBody>> {
  const raw = await readFile(new URL("../../../../fixtures/grant.cesr", import.meta.url));
  const [fwd] = await Array.fromAsync(parse(raw.toString()));
  return embeds(fwd as Message<ExchangeEventBody>).evt as Message<ExchangeEventBody>;
}

function encode(message: Message): string {
  const atc = new Attachments({ PathedMaterialCouples: message.attachments.PathedMaterialCouples });
  return new TextDecoder().decode(message.raw) + encodeText(atc.frames());
}

function makeSessions(): SessionStore & { size: () => number } {
  const entries = new Map<string, string>();
  return {
    get: async (token) => entries.get(token) ?? null,
    put: async (token, cesr) => {
      entries.set(token, cesr);
    },
    size: () => entries.size,
  };
}

function makeApp(sessions: SessionStore) {
  return createRouter(new Verifier({ url: URL_BASE }), sessions);
}

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`${URL_BASE}${path}`, init);
}

/** A grant addressed to `token`, rebuilt around the fixture's real embeds. */
async function presentation(token: string): Promise<string> {
  const grant = await grantFixture();

  return encode(
    keri.exchange({
      sender: grant.body.i,
      route: IPEX_GRANT_ROUTE,
      anchor: { m: token, i: grant.body.a.i },
      embeds: embeds(grant),
    }),
  );
}

const TOKEN = "abcdefghijklmnopqrstuvwx";

describe(basename(import.meta.url), () => {
  test("should serve its own oobi with the controller role", async () => {
    const verifier = new Verifier({ url: URL_BASE });
    const response = await createRouter(verifier, makeSessions())(request("/oobi"));

    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers.get("Keri-Aid"), verifier.aid);

    const body = await response.text();
    assert.ok(body.includes('"role":"controller"'), "expected a controller end role");
    assert.ok(body.includes(URL_BASE), "expected the location scheme to carry the url");
  });

  test("should hand out a session with the verifier aid and oobi", async () => {
    const verifier = new Verifier({ url: URL_BASE });
    const sessions = makeSessions();
    const response = await createRouter(verifier, sessions)(request("/api/sessions", { method: "POST" }));

    assert.strictEqual(response.status, 200);
    const body = (await response.json()) as { token: string; aid: string; oobi: string };

    assert.strictEqual(body.aid, verifier.aid);
    assert.strictEqual(body.oobi, `${URL_BASE}/oobi`);
    assert.match(body.token, /^[A-Za-z0-9_-]{16,64}$/);
    assert.strictEqual(sessions.size(), 0, "creating a session should not write");
  });

  test("should store a presented grant against its session token", async () => {
    const sessions = makeSessions();
    const app = makeApp(sessions);

    const put = await app(request("/", { method: "PUT", body: await presentation(TOKEN) }));
    assert.strictEqual(put.status, 204);

    const read = await app(request(`/api/sessions/${TOKEN}`));
    assert.strictEqual(read.status, 200);

    // The stored stream is what the browser verifies, so it must survive intact.
    const index = await EventIndex.parse(await read.text());
    assert.strictEqual(index.credentials.length, 1);
  });

  test("should report a pending session before anything is presented", async () => {
    const response = await makeApp(makeSessions())(request(`/api/sessions/${TOKEN}`));

    assert.strictEqual(response.status, 204);
  });

  test("should reject a stream carrying no grant", async () => {
    const sessions = makeSessions();
    const response = await makeApp(sessions)(request("/", { method: "PUT", body: "" }));

    assert.strictEqual(response.status, 400);
    assert.strictEqual(sessions.size(), 0);
  });

  test("should reject a grant whose message is not a usable token", async () => {
    const sessions = makeSessions();
    const response = await makeApp(sessions)(request("/", { method: "PUT", body: await presentation("nope") }));

    assert.strictEqual(response.status, 400);
    assert.strictEqual(sessions.size(), 0);
  });

  test("should allow the browser to read a session cross-origin", async () => {
    const response = await makeApp(makeSessions())(request(`/api/sessions/${TOKEN}`));

    assert.strictEqual(response.headers.get("Access-Control-Allow-Origin"), "*");
  });
});
