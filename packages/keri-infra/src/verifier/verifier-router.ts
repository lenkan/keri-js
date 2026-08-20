import { Attachments, encodeText, type Message, parse } from "cesr";
import { encodeBase64Url, encodeUtf8 } from "cesr/encoding";
import type { ExchangeEventBody } from "keri";
import { KeyEventLog, RoutedEvent } from "keri";
import { fetchKel, KelFetchError } from "../http/main.ts";
import { KeriLogger, type Logger } from "../logging/main.ts";
import { generateWords, identityOf, type KeyEventStore, type LoginRecord, recordKeyEvents, wordsKey } from "./login.ts";
import type { SessionStore, Verifier } from "./verifier.ts";

const SESSION_TTL_MS = 10 * 60 * 1000;
const TOKEN_LENGTH = 24;
const TOKEN_PATTERN = /^[A-Za-z0-9]{16,64}$/;
const SESSION_PATH = /^\/api\/sessions\/([A-Za-z0-9]{16,64})$/;
const LOGIN_SESSION_PATH = /^\/api\/login\/sessions\/([A-Za-z0-9]{16,64})(\/kel|\/oobi)?$/;

// Deno KV caps a value at 64 KiB and rejects anything larger, which would
// surface as a 500 long after the holder thinks the grant landed.
const MAX_PRESENTATION_BYTES = 60 * 1024;

// A KEL submission can carry witness receipts, so it gets more headroom than a
// presentation; only the derived state is stored, so KV value caps don't bind.
const MAX_KEL_BYTES = 256 * 1024;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export interface RouterOptions {
  logger?: Logger;
  /** Used for the OOBI pull path; injectable for tests. */
  fetch?: typeof globalThis.fetch;
}

function encodeOobi(events: readonly Message[]): string {
  return events
    .flatMap((message) => {
      const atc = new Attachments({
        ControllerIdxSigs: message.attachments.ControllerIdxSigs,
        NonTransReceiptCouples: message.attachments.NonTransReceiptCouples,
      });
      return [new TextDecoder().decode(message.raw), encodeText(atc.frames())];
    })
    .join("");
}

async function* single(chunk: Uint8Array): AsyncIterable<Uint8Array> {
  yield chunk;
}

type TokenLookup = { ok: true; token: string } | { ok: false; reason: "no-grant" | "no-token" };

/** The session a presentation is addressed to, from where `kli ipex grant --message` puts it. */
function sessionToken(messages: readonly Message[]): TokenLookup {
  for (const message of messages) {
    const body = message.body as Partial<ExchangeEventBody>;

    if (body.t === "exn" && body.r === RoutedEvent.IPEX_GRANT_ROUTE) {
      const token = body.a?.m;
      return typeof token === "string" && token.length > 0 ? { ok: true, token } : { ok: false, reason: "no-token" };
    }
  }

  return { ok: false, reason: "no-grant" };
}

// Base64url's `-` and `_` are dropped rather than remapped: a token starting
// with `-` looks like an option to `kli ipex grant --message`, and argparse
// rejects the command outright.
function createToken(): string {
  let token = "";

  while (token.length < TOKEN_LENGTH) {
    token += encodeBase64Url(crypto.getRandomValues(new Uint8Array(24))).replace(/[^A-Za-z0-9]/g, "");
  }

  return token.slice(0, TOKEN_LENGTH);
}

export function createRouter(
  verifier: Verifier,
  sessions: SessionStore,
  keyEvents: KeyEventStore,
  options: RouterOptions = {},
): (request: Request) => Promise<Response> {
  const log = new KeriLogger(options.logger);
  const oobi = encodeOobi(verifier.events);

  async function readLogin(token: string): Promise<LoginRecord | null> {
    const value = await sessions.get(`login:${token}`);
    return value ? (JSON.parse(value) as LoginRecord) : null;
  }

  async function writeLogin(token: string, record: LoginRecord): Promise<void> {
    await sessions.put(`login:${token}`, JSON.stringify(record), SESSION_TTL_MS);
  }

  async function handlePresentation(request: Request): Promise<Response> {
    // KERIpy's sendDirect PUTs the whole stream inline; KERI-JS senders detach
    // the attachments to a header. Either way we store exactly what arrived,
    // because the browser re-parses it to verify.
    const attachment = request.headers.get("CESR-ATTACHMENT") ?? "";

    // Buffering first and measuring after would let an unauthenticated caller
    // decide how much memory to allocate. Content-Length is advisory, so the
    // measured check below still stands for chunked bodies.
    const declared = Number(request.headers.get("Content-Length"));
    if (declared > MAX_PRESENTATION_BYTES) {
      log.warn("rejecting oversized presentation", { size: declared });
      return Response.json({ error: "Presentation too large" }, { status: 413 });
    }

    const stream = (await request.text()) + attachment;

    const size = new TextEncoder().encode(stream).length;
    if (size > MAX_PRESENTATION_BYTES) {
      log.warn("rejecting oversized presentation", { size });
      return Response.json({ error: "Presentation too large" }, { status: 413 });
    }

    // The body is unauthenticated, so anything that is not a CESR stream has to
    // come back as a 400 rather than escaping as a 500.
    let messages: Message[];
    try {
      messages = await Array.fromAsync(parse(stream));
    } catch (cause) {
      log.warn("could not parse presentation", { error: cause instanceof Error ? cause.message : String(cause) });
      return Response.json({ error: "Could not parse the CESR stream" }, { status: 400 });
    }

    const challenge = messages.find((message) => {
      const body = message.body as Partial<ExchangeEventBody>;
      return body.t === "exn" && body.r === RoutedEvent.CHALLENGE_RESPONSE_ROUTE;
    });
    if (challenge) {
      return handleChallengeResponse(challenge as Message<ExchangeEventBody>);
    }

    const lookup = sessionToken(messages);

    if (!lookup.ok) {
      log.warn(`rejecting presentation: ${lookup.reason}`, { messages: messages.length });
      const error =
        lookup.reason === "no-grant"
          ? "No IPEX grant found"
          : "The grant carries no session token, pass it as --message";
      return Response.json({ error }, { status: 400 });
    }

    if (!TOKEN_PATTERN.test(lookup.token)) {
      log.warn("rejecting malformed session token");
      return Response.json({ error: "Malformed session token" }, { status: 400 });
    }

    await sessions.put(lookup.token, stream, SESSION_TTL_MS);
    log.debug("stored presentation", { messages: messages.length });

    return new Response(null, { status: 204 });
  }

  async function handleSessionRead(token: string): Promise<Response> {
    const cesr = await sessions.get(token);

    if (!cesr) {
      return new Response(null, { status: 204 });
    }

    return new Response(cesr, { status: 200, headers: { "Content-Type": "application/json+cesr" } });
  }

  /** Both KEL intake paths converge here once a verified log exists. */
  async function challenge(token: string, kel: KeyEventLog): Promise<Response> {
    const recorded = await recordKeyEvents(keyEvents, kel);
    if (!recorded.ok) {
      log.warn("rejecting conflicting key event history", { aid: recorded.aid, sn: recorded.sn.toString() });
      return Response.json(
        { error: `Conflicting key event history for ${recorded.aid} at sequence number ${recorded.sn}` },
        { status: 409 },
      );
    }

    const aid = kel.state.identifier;
    const words = generateWords();

    await writeLogin(token, { phase: "challenged", aid, state: kel.state, words });
    await sessions.put(`words:${wordsKey(words)}`, token, SESSION_TTL_MS);
    log.debug("issued challenge", { aid });

    return Response.json({ aid, words });
  }

  async function handleKelSubmission(request: Request, token: string): Promise<Response> {
    const declared = Number(request.headers.get("Content-Length"));
    if (declared > MAX_KEL_BYTES) {
      return Response.json({ error: "Key event log too large" }, { status: 413 });
    }

    const text = await request.text();
    if (encodeUtf8(text).length > MAX_KEL_BYTES) {
      return Response.json({ error: "Key event log too large" }, { status: 413 });
    }

    let kel: KeyEventLog;
    try {
      kel = await KeyEventLog.parse(single(encodeUtf8(text)), { allowPartiallyWitnessed: true });
    } catch (cause) {
      log.warn("could not parse submitted KEL", { error: cause instanceof Error ? cause.message : String(cause) });
      return Response.json({ error: "The body is not a valid key event log" }, { status: 400 });
    }

    return challenge(token, kel);
  }

  async function handleOobiSubmission(request: Request, token: string): Promise<Response> {
    let url: string;
    try {
      const body = (await request.json()) as { url?: unknown };
      url = typeof body.url === "string" ? body.url : "";
    } catch {
      url = "";
    }

    if (!/^https?:\/\//.test(url)) {
      return Response.json({ error: "Pass a JSON body with an http(s) `url`" }, { status: 400 });
    }

    let kel: KeyEventLog;
    try {
      kel = await fetchKel(url, { fetch: options.fetch, maxBytes: MAX_KEL_BYTES });
    } catch (cause) {
      const error = cause instanceof Error ? cause.message : String(cause);
      log.warn("could not resolve OOBI", { error });
      return cause instanceof KelFetchError
        ? Response.json({ error: `Could not fetch the OOBI: ${error}` }, { status: 502 })
        : Response.json({ error: `The OOBI did not resolve to a valid key event log` }, { status: 400 });
    }

    return challenge(token, kel);
  }

  async function handleLoginRead(token: string): Promise<Response> {
    const record = await readLogin(token);

    if (!record) {
      return new Response(null, { status: 204 });
    }

    if (record.phase === "authenticated") {
      return Response.json({ phase: record.phase, identity: identityOf(record) });
    }

    return Response.json({ phase: record.phase, aid: record.aid, words: record.words, error: record.error });
  }

  async function handleChallengeResponse(message: Message<ExchangeEventBody>): Promise<Response> {
    const words = message.body.a?.words;
    if (!Array.isArray(words) || words.length === 0 || !words.every((word) => typeof word === "string")) {
      return Response.json({ error: "The challenge response carries no words" }, { status: 400 });
    }

    // The response has no token field, so the words are the correlator. The
    // token lookup can trail a just-written mapping on another KV colo — hence
    // the retry hint.
    const token = await sessions.get(`words:${wordsKey(words)}`);
    const record = token ? await readLogin(token) : null;

    if (!token || !record) {
      log.warn("challenge response for unknown words");
      return Response.json({ error: "Unknown or expired challenge — retry in a moment" }, { status: 404 });
    }

    if (record.phase === "authenticated") {
      log.warn("replayed challenge response", { aid: record.aid });
      return Response.json({ error: "Challenge already used" }, { status: 410 });
    }

    if (record.words.join(" ") !== words.join(" ")) {
      // A stale words mapping from before a re-submission re-challenged.
      return Response.json({ error: "Unknown or expired challenge — retry in a moment" }, { status: 404 });
    }

    if (message.body.i !== record.aid || message.body.a.i !== record.aid) {
      const error = "The response is signed by a different AID than the submitted key event log";
      await writeLogin(token, { ...record, error });
      return Response.json({ error }, { status: 400 });
    }

    const verdict = RoutedEvent.verifyExchange(message, record.state);
    if (!verdict.ok) {
      log.warn("rejecting challenge response", { aid: record.aid, kind: verdict.kind, error: verdict.error });
      const stale = verdict.kind === "stale-establishment";
      const error = stale
        ? "Key event log out of date — re-run the export step after rotating, then respond again"
        : `Invalid challenge response: ${verdict.error}`;
      await writeLogin(token, { ...record, error });
      return Response.json({ error }, { status: stale ? 409 : 400 });
    }

    await writeLogin(token, {
      phase: "authenticated",
      aid: record.aid,
      state: record.state,
      authenticatedAt: new Date().toISOString(),
    });
    log.debug("authenticated", { aid: record.aid });

    return new Response(null, { status: 204 });
  }

  // The whole surface is public and unauthenticated, so every response carries
  // the same headers rather than each branch remembering them.
  return async function handler(request: Request): Promise<Response> {
    const response = await route(request);

    for (const [header, value] of Object.entries(CORS_HEADERS)) {
      response.headers.set(header, value);
    }

    return response;
  };

  async function route(request: Request): Promise<Response> {
    const { method } = request;
    const pathname = new URL(request.url).pathname;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204 });
    }

    if (pathname === "/") {
      switch (method) {
        case "GET":
          return Response.json({ status: "OK" });
        case "PUT":
        case "POST":
          return handlePresentation(request);
        default:
          return new Response("Method Not Allowed", { status: 405 });
      }
    }

    if (pathname === "/oobi" || pathname.startsWith("/oobi/")) {
      if (method !== "GET") {
        return new Response("Method Not Allowed", { status: 405 });
      }

      log.debug("serving oobi");
      return new Response(oobi, {
        status: 200,
        headers: { "Content-Type": "application/json+cesr", "Keri-Aid": verifier.aid },
      });
    }

    // Deliberately writes nothing: a token only has to exist by the time a
    // grant arrives, so sessions cost no storage until they are used.
    if (pathname === "/api/sessions" && method === "POST") {
      return Response.json({ token: createToken(), aid: verifier.aid, oobi: verifier.oobi });
    }

    // Also writes nothing — the login TTL clock starts at KEL submission, so a
    // slow keripy install can't expire the wizard.
    if (pathname === "/api/login/sessions" && method === "POST") {
      return Response.json({ token: createToken(), aid: verifier.aid, oobi: verifier.oobi });
    }

    const login = pathname.match(LOGIN_SESSION_PATH);
    if (login) {
      const [, token, sub] = login;

      if (sub === "/kel" && method === "POST") {
        return handleKelSubmission(request, token);
      }
      if (sub === "/oobi" && method === "POST") {
        return handleOobiSubmission(request, token);
      }
      if (!sub && method === "GET") {
        return handleLoginRead(token);
      }

      return new Response("Method Not Allowed", { status: 405 });
    }

    const session = pathname.match(SESSION_PATH);
    if (session && method === "GET") {
      return handleSessionRead(session[1]);
    }

    return new Response("Not Found", { status: 404 });
  }
}
