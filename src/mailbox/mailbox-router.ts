import { Attachments, encodeText, parse } from "#keri/cesr";
import { normalizeLogger, type PartialLogger } from "#keri/logging";
import type { Mailbox, MailboxEvent, MailboxReply } from "./mailbox.ts";

const RETRY_MS = 5000;

export interface RouterOptions {
  logger?: PartialLogger;
}

function createOobiResponse(events: readonly MailboxEvent[]): Response {
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

function encodeReply(reply: MailboxReply): string {
  const atc = new Attachments({
    ControllerIdxSigs: reply.message.attachments.ControllerIdxSigs,
    WitnessIdxSigs: reply.message.attachments.WitnessIdxSigs,
    NonTransReceiptCouples: reply.message.attachments.NonTransReceiptCouples,
    TransIdxSigGroups: reply.message.attachments.TransIdxSigGroups,
    PathedMaterialCouples: reply.message.attachments.PathedMaterialCouples,
  });
  const cesr = new TextDecoder().decode(reply.message.raw) + encodeText(atc.frames());
  return `id: ${reply.id}\nevent: ${reply.topic}\nretry: ${RETRY_MS}\ndata: ${cesr}\n\n`;
}

function createResponse(replies: readonly MailboxReply[]): Response {
  if (replies.length === 0) {
    return new Response(null, { status: 204 });
  }

  const body = replies.map(encodeReply).join("");

  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
}

export function createRouter(mailbox: Mailbox, options: RouterOptions = {}): (request: Request) => Promise<Response> {
  const log = normalizeLogger(options.logger);

  async function handleMessageRequest(request: Request): Promise<Response> {
    const atc = request.headers.get("CESR-ATTACHMENT");
    if (!atc) {
      log.warn("rejecting POST /: missing CESR-ATTACHMENT");
      return Response.json({ error: "Bad Request" }, { status: 400 });
    }

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
    return createResponse(replies);
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

    if (pathname.startsWith("/oobi")) {
      switch (method) {
        case "GET": {
          log.debug("GET /oobi: serving self", { count: mailbox.events.length });
          const response = createOobiResponse(mailbox.events);
          response.headers.set("Keri-Aid", mailbox.aid);
          return response;
        }
        default:
          return new Response("Method Not Allowed", { status: 405 });
      }
    }

    return new Response("Not Found", { status: 404 });
  };
}
