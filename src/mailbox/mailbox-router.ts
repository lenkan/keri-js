import { Attachments, encodeText, parse } from "#keri/cesr";
import type { Message } from "#keri/core";
import type { Mailbox, MailboxEvent } from "./mailbox.ts";

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

function createResponse(messages: readonly Message[]): Response {
  if (messages.length === 0) {
    return new Response(null, { status: 204 });
  }

  const cesr = messages
    .flatMap((message) => {
      const atc = new Attachments({
        ControllerIdxSigs: message.attachments.ControllerIdxSigs,
        WitnessIdxSigs: message.attachments.WitnessIdxSigs,
        NonTransReceiptCouples: message.attachments.NonTransReceiptCouples,
        TransIdxSigGroups: message.attachments.TransIdxSigGroups,
        PathedMaterialCouples: message.attachments.PathedMaterialCouples,
      });
      return [new TextDecoder().decode(message.raw), encodeText(atc.frames())];
    })
    .join("");

  return new Response(`data: ${cesr}\n\n`, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
}

export function createRouter(mailbox: Mailbox): (request: Request) => Promise<Response> {
  async function handleMessageRequest(request: Request): Promise<Response> {
    const atc = request.headers.get("CESR-ATTACHMENT");
    if (!atc) {
      return Response.json({ error: "Bad Request" }, { status: 400 });
    }

    const bodyText = await request.text();
    const replies: Message[] = [];
    for await (const event of parse(bodyText + atc)) {
      for await (const reply of mailbox.handleMessage(event)) {
        replies.push(reply);
      }
    }

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
