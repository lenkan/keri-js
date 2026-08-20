import { Attachments, encodeText, type Message, parse } from "cesr";
import { encodeBase64Url } from "cesr/encoding";
import type { ExchangeEventBody } from "keri";
import { RoutedEvent } from "keri";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { KeyEventStore } from "./login.ts";
import { createLoginHandlers } from "./login-router.ts";
import type { SessionStore, Verifier } from "./verifier.ts";

const SESSION_TTL_MS = 10 * 60 * 1000;
const TOKEN_LENGTH = 24;
const TOKEN_PATTERN = /^[A-Za-z0-9]{16,64}$/;
const SESSION_PATH = /^\/api\/sessions\/([A-Za-z0-9]{16,64})$/;
const LOGIN_SESSION_PATH = /^\/api\/login\/sessions\/([A-Za-z0-9]{16,64})(\/kel|\/oobi)?$/;

// Deno KV caps a value at 64 KiB and rejects anything larger, which would
// surface as a 500 long after the holder thinks the grant landed.
const MAX_PRESENTATION_BYTES = 60 * 1024;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export interface RouterOptions {
  logger?: Logger;
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
  const login = createLoginHandlers({ sessions, keyEvents, log, sessionTtlMs: SESSION_TTL_MS, fetch: options.fetch });

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
      return login.handleChallengeResponse(challenge as Message<ExchangeEventBody>);
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

    // Deliberately writes nothing: a token only has to exist by the time a grant
    // or a KEL arrives, so sessions cost no storage until they are used, and the
    // login TTL clock starts at KEL submission rather than at mint.
    if ((pathname === "/api/sessions" || pathname === "/api/login/sessions") && method === "POST") {
      return Response.json({ token: createToken(), aid: verifier.aid, oobi: verifier.oobi });
    }

    const loginPath = pathname.match(LOGIN_SESSION_PATH);
    if (loginPath) {
      const [, token, sub] = loginPath;

      if (sub === "/kel" && method === "POST") {
        return login.handleKelSubmission(request, token);
      }
      if (sub === "/oobi" && method === "POST") {
        return login.handleOobiSubmission(request, token);
      }
      if (!sub && method === "GET") {
        return login.handleLoginRead(token);
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
