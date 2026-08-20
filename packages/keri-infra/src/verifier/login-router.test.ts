import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Attachments, encodeText, Indexer, type Message } from "cesr";
import type { KeyEventBody, KeyPair, KeyState } from "keri";
import { generateKeyPair, KeyEvent, RoutedEvent } from "keri";
import { makeKeyEvents, makeSessions } from "./stores.test.ts";
import type { SessionStore } from "./verifier.ts";
import { Verifier } from "./verifier.ts";
import { createRouter } from "./verifier-router.ts";

const URL_BASE = "http://localhost:3002";

function sign(payload: Uint8Array, options: { key: Uint8Array; index: number }): string {
  return encodeText(Indexer.crypto.ed25519_sig(ed25519.sign(payload, options.key), options.index));
}

interface User {
  aid: string;
  keys: KeyPair[];
  events: Message<KeyEventBody>[];
  state: { s: string; d: string };
}

function encode(events: Message[]): string {
  return events.map((event) => new TextDecoder().decode(event.raw) + encodeText(event.attachments.frames())).join("");
}

function makeUser(): User {
  const key0 = generateKeyPair();
  const key1 = generateKeyPair();

  const icp = KeyEvent.incept({ signingKeys: [key0.publicKey], nextKeyDigests: [key1.publicKeyDigest] });
  icp.attachments.ControllerIdxSigs.push(sign(icp.raw, { key: key0.privateKey, index: 0 }));

  return {
    aid: icp.body.i,
    keys: [key0, key1],
    events: [icp as Message<KeyEventBody>],
    state: { s: icp.body.s, d: icp.body.d },
  };
}

function rotateUser(user: User): User {
  const [key0, key1] = user.keys.slice(-2);
  const key2 = generateKeyPair();

  const state: KeyState = {
    identifier: user.aid,
    signingThreshold: "1",
    signingKeys: [key0.publicKey],
    nextThreshold: "1",
    nextKeyDigests: [key1.publicKeyDigest],
    backerThreshold: "0",
    backers: [],
    configTraits: [],
    lastEvent: { i: user.aid, s: user.state.s, d: user.state.d },
    lastEstablishment: { i: user.aid, s: user.state.s, d: user.state.d },
  };

  const rot = KeyEvent.rotate(state, { signingKeys: [key1.publicKey], nextKeyDigests: [key2.publicKeyDigest] });
  rot.attachments.ControllerIdxSigs.push(sign(rot.raw, { key: key1.privateKey, index: 0 }));

  return {
    aid: user.aid,
    keys: [key1, key2],
    events: [...user.events, rot as Message<KeyEventBody>],
    state: { s: rot.body.s, d: rot.body.d },
  };
}

/** The exact wire shape of KERIpy's sendDirect: exn JSON body, non-pipelined `-F` group in the header. */
function respond(user: User, words: string[], overrides: { key?: KeyPair; seal?: { s: string; d: string } } = {}) {
  const key = overrides.key ?? user.keys[user.keys.length - 2];
  const seal = overrides.seal ?? user.state;

  const exn = RoutedEvent.exchange({
    sender: user.aid,
    route: RoutedEvent.CHALLENGE_RESPONSE_ROUTE,
    anchor: { i: user.aid, words },
  });

  const attachments = new Attachments({
    TransIdxSigGroups: [
      {
        prefix: user.aid,
        snu: seal.s,
        digest: seal.d,
        ControllerIdxSigs: [sign(exn.raw, { key: key.privateKey, index: 0 })],
      },
    ],
  });

  return request("/", {
    method: "POST",
    body: new TextDecoder().decode(exn.raw),
    headers: {
      "Content-Type": "application/cesr+json",
      "CESR-ATTACHMENT": encodeText(attachments.frames().slice(1)),
    },
  });
}

function request(path: string, init: RequestInit = {}): Request {
  return new Request(`${URL_BASE}${path}`, init);
}

interface App {
  handler: (request: Request) => Promise<Response>;
  sessions: SessionStore & { size: () => number };
}

async function makeApp(options: { fetch?: typeof globalThis.fetch } = {}): Promise<App> {
  const sessions = makeSessions();
  const handler = createRouter(await Verifier.create({ url: URL_BASE }), sessions, makeKeyEvents(), options);
  return { handler, sessions };
}

async function mint(app: App): Promise<string> {
  const response = await app.handler(request("/api/login/sessions", { method: "POST" }));
  const { token } = (await response.json()) as { token: string };
  return token;
}

async function submit(app: App, token: string, user: User): Promise<Response> {
  return app.handler(request(`/api/login/sessions/${token}/kel`, { method: "POST", body: encode(user.events) }));
}

async function status(app: App, token: string): Promise<{ status: number; body?: Record<string, unknown> }> {
  const response = await app.handler(request(`/api/login/sessions/${token}`));
  if (response.status === 204) {
    return { status: 204 };
  }
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe(basename(import.meta.url), () => {
  test("should mint a login session without writing anything", async () => {
    const app = await makeApp();
    const response = await app.handler(request("/api/login/sessions", { method: "POST" }));

    assert.strictEqual(response.status, 200);
    const body = (await response.json()) as Record<string, unknown>;
    assert.match(String(body.token), /^[A-Za-z0-9]{24}$/);
    assert.strictEqual(app.sessions.size(), 0);
  });

  test("should challenge a pushed KEL", async () => {
    const app = await makeApp();
    const user = makeUser();
    const token = await mint(app);

    const response = await submit(app, token, user);
    assert.strictEqual(response.status, 200);

    const body = (await response.json()) as { aid: string; words: string[] };
    assert.strictEqual(body.aid, user.aid);
    assert.strictEqual(body.words.length, 12);

    const read = await status(app, token);
    assert.strictEqual(read.status, 200);
    assert.strictEqual(read.body?.phase, "challenged");
    assert.deepStrictEqual(read.body?.words, body.words);
  });

  test("should reject a body that is not a KEL", async () => {
    const app = await makeApp();
    const token = await mint(app);

    const response = await app.handler(
      request(`/api/login/sessions/${token}/kel`, { method: "POST", body: "not cesr" }),
    );
    assert.strictEqual(response.status, 400);
  });

  test("should reject an oversized KEL, declared or measured", async () => {
    const app = await makeApp();
    const token = await mint(app);

    const declared = await app.handler(
      request(`/api/login/sessions/${token}/kel`, {
        method: "POST",
        body: "x",
        headers: { "Content-Length": String(1024 * 1024) },
      }),
    );
    assert.strictEqual(declared.status, 413);

    const measured = await app.handler(
      request(`/api/login/sessions/${token}/kel`, { method: "POST", body: "x".repeat(257 * 1024) }),
    );
    assert.strictEqual(measured.status, 413);
  });

  test("should challenge a pulled OOBI", async () => {
    const user = makeUser();
    const app = await makeApp({ fetch: async () => new Response(encode(user.events)) });
    const token = await mint(app);

    const response = await app.handler(
      request(`/api/login/sessions/${token}/oobi`, {
        method: "POST",
        body: JSON.stringify({ url: "http://witness.example/oobi/aid" }),
      }),
    );

    assert.strictEqual(response.status, 200);
    const body = (await response.json()) as { aid: string };
    assert.strictEqual(body.aid, user.aid);
  });

  test("should return 502 when the OOBI fetch fails and 400 for a bad URL", async () => {
    const app = await makeApp({
      fetch: async () => {
        throw new Error("connection refused");
      },
    });
    const token = await mint(app);

    const failed = await app.handler(
      request(`/api/login/sessions/${token}/oobi`, {
        method: "POST",
        body: JSON.stringify({ url: "http://witness.example/oobi/aid" }),
      }),
    );
    assert.strictEqual(failed.status, 502);

    const bad = await app.handler(
      request(`/api/login/sessions/${token}/oobi`, {
        method: "POST",
        body: JSON.stringify({ url: "file:///etc/passwd" }),
      }),
    );
    assert.strictEqual(bad.status, 400);
  });

  test("should re-challenge on re-submission", async () => {
    const app = await makeApp();
    const user = makeUser();
    const token = await mint(app);

    const first = (await (await submit(app, token, user)).json()) as { words: string[] };
    const rotated = rotateUser(user);
    const second = (await (await submit(app, token, rotated)).json()) as { words: string[] };

    assert.notDeepStrictEqual(second.words, first.words);

    const read = await status(app, token);
    assert.deepStrictEqual(read.body?.words, second.words);
  });

  test("should refuse a forked KEL as duplicity while accepting an extension", async () => {
    const app = await makeApp();
    const user = makeUser();

    await submit(app, await mint(app), user);

    // A clean rotation extends the stored history.
    const rotated = rotateUser(user);
    const extension = await submit(app, await mint(app), rotated);
    assert.strictEqual(extension.status, 200);

    // A different rotation at the same sequence number is a fork.
    const forked = rotateUser(user);
    const fork = await submit(app, await mint(app), forked);
    assert.strictEqual(fork.status, 409);
    const body = (await fork.json()) as { error: string };
    assert.match(body.error, /[Cc]onflicting key event history/);
  });

  test("should authenticate a valid challenge response, once", async () => {
    const app = await makeApp();
    const user = makeUser();
    const token = await mint(app);
    const { words } = (await (await submit(app, token, user)).json()) as { words: string[] };

    const accepted = await app.handler(respond(user, words));
    assert.strictEqual(accepted.status, 204);

    const read = await status(app, token);
    assert.strictEqual(read.body?.phase, "authenticated");
    const identity = read.body?.identity as Record<string, unknown>;
    assert.strictEqual(identity.aid, user.aid);
    assert.strictEqual(identity.sequenceNumber, 0);
    assert.deepStrictEqual(identity.witnesses, []);

    const replayed = await app.handler(respond(user, words));
    assert.strictEqual(replayed.status, 410);
  });

  test("should reject unknown words", async () => {
    const app = await makeApp();
    const user = makeUser();
    await submit(app, await mint(app), user);

    const response = await app.handler(respond(user, ["wrong", "words", "entirely"]));
    assert.strictEqual(response.status, 404);
  });

  test("should reject a response signed with the wrong key", async () => {
    const app = await makeApp();
    const user = makeUser();
    const token = await mint(app);
    const { words } = (await (await submit(app, token, user)).json()) as { words: string[] };

    const response = await app.handler(respond(user, words, { key: generateKeyPair() }));
    assert.strictEqual(response.status, 400);

    const read = await status(app, token);
    assert.strictEqual(read.body?.phase, "challenged");
    assert.match(String(read.body?.error), /Invalid challenge response/);
  });

  test("should surface a stale seal as a retryable error", async () => {
    const app = await makeApp();
    const user = makeUser();
    const rotated = rotateUser(user);
    const token = await mint(app);
    const { words } = (await (await submit(app, token, rotated)).json()) as { words: string[] };

    // Signed with the pre-rotation key, sealed to the icp.
    const response = await app.handler(respond(rotated, words, { key: user.keys[0], seal: user.state }));
    assert.strictEqual(response.status, 409);

    const read = await status(app, token);
    assert.strictEqual(read.body?.phase, "challenged");
    assert.match(String(read.body?.error), /out of date/);

    // Recovery: a response sealed to the rotation with the rotated key.
    const retried = await app.handler(respond(rotated, words));
    assert.strictEqual(retried.status, 204);
  });
});
