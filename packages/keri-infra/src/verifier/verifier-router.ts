import { Attachments, encodeText, parse } from "cesr";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { SessionStore, Verifier, VerifierEvent } from "./verifier.ts";

const SESSION_TTL_MS = 10 * 60 * 1000;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export interface RouterOptions {
  logger?: Logger;
}

function createOobiResponse(events: readonly VerifierEvent[]): Response {
  const body = events
    .flatMap(({ message }) => {
      const atc = new Attachments({
        ControllerIdxSigs: message.attachments.ControllerIdxSigs,
        NonTransReceiptCouples: message.attachments.NonTransReceiptCouples,
      });
      return [new TextDecoder().decode(message.raw), encodeText(atc.frames())];
    })
    .join("");

  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json+cesr" },
  });
}

function createToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export function createRouter(
  verifier: Verifier,
  sessions: SessionStore,
  options: RouterOptions = {},
): (request: Request) => Promise<Response> {
  const log = new KeriLogger(options.logger);

  async function handlePresentation(request: Request): Promise<Response> {
    // KERIpy's sendDirect PUTs the whole stream inline; KERI-JS senders detach
    // the attachments to a header. Either way we store exactly what arrived,
    // because the browser re-parses it to verify.
    const attachment = request.headers.get("CESR-ATTACHMENT") ?? "";
    const stream = (await request.text()) + attachment;

    const messages = await Array.fromAsync(parse(stream));
    const token = verifier.sessionToken(messages);

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
    if (!TOKEN_PATTERN.test(token)) {
      return Response.json({ error: "Not Found" }, { status: 404, headers: CORS_HEADERS });
    }

    const cesr = await sessions.get(token);

    if (!cesr) {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    return new Response(cesr, {
      status: 200,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json+cesr" },
    });
  }

  return async function handler(request: Request): Promise<Response> {
    const { method } = request;
    const pathname = new URL(request.url).pathname;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
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

      log.debug("serving oobi", { count: verifier.events.length });
      const response = createOobiResponse(verifier.events);
      response.headers.set("Keri-Aid", verifier.aid);
      return response;
    }

    // Deliberately writes nothing: a token only has to exist by the time a
    // grant arrives, so sessions cost no storage until they are used.
    if (pathname === "/api/sessions" && method === "POST") {
      return Response.json({ token: createToken(), aid: verifier.aid, oobi: verifier.oobi }, { headers: CORS_HEADERS });
    }

    const session = pathname.match(/^\/api\/sessions\/([^/]+)$/);
    if (session && method === "GET") {
      return handleSessionRead(session[1]);
    }

    return new Response("Not Found", { status: 404 });
  };
}
