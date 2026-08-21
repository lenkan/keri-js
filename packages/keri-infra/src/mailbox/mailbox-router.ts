import { encodeText, type Message, parse } from "cesr";
import { KeriLogger, type Logger } from "../logging/main.ts";
import type { Mailbox, MailboxReply } from "./mailbox.ts";
import { createMailboxResponse } from "./sse.ts";

export interface RouterOptions {
  logger?: Logger;
}

function encodeMessages(messages: readonly Message[]): string {
  return messages
    .flatMap((message) => [new TextDecoder().decode(message.raw), encodeText(message.attachments.frames())])
    .join("");
}

function createOobiResponse(messages: readonly Message[], aid: string): Response {
  return new Response(encodeMessages(messages), {
    status: 200,
    headers: { "Content-Type": "application/json+cesr", "Keri-Aid": aid },
  });
}

export function createRouter(mailbox: Mailbox, options: RouterOptions = {}): (request: Request) => Promise<Response> {
  const log = new KeriLogger(options.logger);

  async function handleMessageRequest(request: Request): Promise<Response> {
    // Attachments arrive either detached in the header (KERIpy, MailboxClient)
    // or already inline in the body (the worker forwards merged streams).
    const atc = request.headers.get("CESR-ATTACHMENT") ?? "";

    const bodyText = await request.text();
    const replies: MailboxReply[] = [];
    let count = 0;
    for await (const event of parse(bodyText + atc)) {
      count++;
      for await (const reply of mailbox.handleMessage(event)) {
        replies.push(reply);
      }
    }

    log.debug("POST /: handled messages", { count, replies: replies.length });
    return createMailboxResponse(replies);
  }

  // The `kli mailbox add` contract: multipart form with the controller's full
  // KEL and its signed /end/role/add naming this mailbox; a plain 200 means
  // enrolled.
  async function handleEnrollment(request: Request): Promise<Response> {
    let kel: unknown;
    let rpy: unknown;
    try {
      const form = await request.formData();
      kel = form.get("kel");
      rpy = form.get("rpy");
    } catch (cause) {
      log.warn("rejecting POST /mailboxes: unreadable form data", {
        error: cause instanceof Error ? cause.message : String(cause),
      });
      return Response.json({ error: "Expected multipart form data with kel and rpy fields" }, { status: 400 });
    }

    if (typeof kel !== "string" || typeof rpy !== "string") {
      return Response.json({ error: "Expected multipart form data with kel and rpy fields" }, { status: 400 });
    }

    const result = await mailbox.enroll(kel, rpy);
    if (!result.ok) {
      log.warn("rejecting enrollment", { error: result.error });
      return Response.json({ error: result.error }, { status: 400 });
    }

    log.debug("enrolled", { aid: result.aid });
    return Response.json({ aid: result.aid });
  }

  return async function handler(request: Request): Promise<Response> {
    const { method } = request;
    const pathname = new URL(request.url).pathname;

    if (pathname === "/") {
      switch (method) {
        case "GET":
          return Response.json({ status: "OK" });
        case "POST":
          return handleMessageRequest(request);
        default:
          return new Response("Method Not Allowed", { status: 405 });
      }
    }

    if (pathname === "/mailboxes") {
      if (method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return handleEnrollment(request);
    }

    if (pathname.startsWith("/oobi")) {
      if (method !== "GET") {
        return new Response("Method Not Allowed", { status: 405 });
      }

      const aid = pathname.split("/")[2];

      if (!aid || aid === mailbox.aid) {
        log.debug("GET /oobi: serving self", { count: mailbox.events.length });
        return createOobiResponse(
          mailbox.events.map((event) => event.message),
          mailbox.aid,
        );
      }

      const messages = mailbox.serveOobi(aid);
      if (!messages) {
        log.debug("GET /oobi: unknown aid", { aid });
        return new Response("Not Found", { status: 404 });
      }

      log.debug("GET /oobi: serving enrolled aid", { aid, count: messages.length });
      return createOobiResponse(messages, aid);
    }

    return new Response("Not Found", { status: 404 });
  };
}
