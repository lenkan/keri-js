import { Attachments, encodeText, type Message, parse } from "cesr";
import { encodeBase64Url } from "cesr/encoding";
import type { ExchangeEventBody } from "keri";
import { IPEX_GRANT_ROUTE } from "keri";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { SessionStore, Verifier } from "./verifier.ts";

const SESSION_TTL_MS = 10 * 60 * 1000;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const SESSION_PATH = /^\/api\/sessions\/([A-Za-z0-9_-]{16,64})$/;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export interface RouterOptions {
  logger?: Logger;
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

/** The session a presentation is addressed to, from where `kli ipex grant --message` puts it. */
function sessionToken(messages: readonly Message[]): string | null {
  for (const message of messages) {
    const body = message.body as Partial<ExchangeEventBody>;

    if (body.t === "exn" && body.r === IPEX_GRANT_ROUTE) {
      const token = body.a?.m;
      return typeof token === "string" && token.length > 0 ? token : null;
    }
  }

  return null;
}

function createToken(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(24)));
}

export function createRouter(
  verifier: Verifier,
  sessions: SessionStore,
  options: RouterOptions = {},
): (request: Request) => Promise<Response> {
  const log = new KeriLogger(options.logger);
  const oobi = encodeOobi(verifier.events);

  async function handlePresentation(request: Request): Promise<Response> {
    // KERIpy's sendDirect PUTs the whole stream inline; KERI-JS senders detach
    // the attachments to a header. Either way we store exactly what arrived,
    // because the browser re-parses it to verify.
    const attachment = request.headers.get("CESR-ATTACHMENT") ?? "";
    const stream = (await request.text()) + attachment;

    const messages = await Array.fromAsync(parse(stream));
    const token = sessionToken(messages);

    if (!token) {
      log.warn("no grant in presentation", { messages: messages.length });
      return Response.json({ error: "No IPEX grant found" }, { status: 400 });
    }

    if (!TOKEN_PATTERN.test(token)) {
      log.warn("rejecting malformed session token");
      return Response.json({ error: "Malformed session token" }, { status: 400 });
    }

    await sessions.put(token, stream, SESSION_TTL_MS);
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

    // Deliberately writes nothing: a token only has to exist by the time a
    // grant arrives, so sessions cost no storage until they are used.
    if (pathname === "/api/sessions" && method === "POST") {
      return Response.json({ token: createToken(), aid: verifier.aid, oobi: verifier.oobi });
    }

    const session = pathname.match(SESSION_PATH);
    if (session && method === "GET") {
      return handleSessionRead(session[1]);
    }

    return new Response("Not Found", { status: 404 });
  }
}
