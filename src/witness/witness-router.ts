import { Attachments, encodeText, parse } from "#keri/cesr";
import type { KeyEvent, KeyEventBody } from "#keri/core";
import type { Logger } from "#keri/logging";
import { type Witness, WitnessError, type WitnessEvent } from "./witness.ts";

export interface RouterOptions {
  logger?: Logger;
}

function createResponse(events: readonly WitnessEvent[]): Response {
  const body = events
    .flatMap(({ message, timestamp }) => {
      const atc = new Attachments({
        ControllerIdxSigs: message.attachments.ControllerIdxSigs,
        WitnessIdxSigs: message.attachments.WitnessIdxSigs,
        NonTransReceiptCouples: message.attachments.NonTransReceiptCouples,
        FirstSeenReplayCouples: [{ fnu: String((message.body as KeyEventBody).s ?? "0"), dt: timestamp }],
      });
      return [new TextDecoder().decode(message.raw), encodeText(atc.frames())];
    })
    .join("");

  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json+cesr" },
  });
}

export function createRouter(witness: Witness, options: RouterOptions = {}): (request: Request) => Promise<Response> {
  const log = options.logger;

  async function handleReceiptRequest(request: Request): Promise<Response> {
    const atc = request.headers.get("CESR-ATTACHMENT");
    if (!atc) {
      log?.warn("rejecting POST /receipts: missing CESR-ATTACHMENT");
      return Response.json({ error: "Bad Request" }, { status: 400 });
    }

    const bodyText = await request.text();
    const receipts: WitnessEvent[] = [];

    for await (const witnessEvent of parse(bodyText + atc)) {
      try {
        const receipt = witness.receipt(witnessEvent as KeyEvent);
        receipts.push({ message: receipt, timestamp: new Date() });
      } catch (err) {
        if (err instanceof WitnessError) {
          log?.warn("rejecting POST /receipts", { error: err.message });
          return Response.json({ error: "Bad Request" }, { status: 400 });
        }
        throw err;
      }
    }

    log?.debug("POST /receipts: issued receipts", { count: receipts.length });
    return createResponse(receipts);
  }

  async function handleOobiRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const aid = url.pathname.split("/")[2];
    let response: Response;
    if (aid === undefined || aid === witness.aid) {
      log?.debug("GET /oobi: serving self", { count: witness.events.length });
      response = createResponse(witness.events);
    } else {
      const events = Array.from(witness.getKeyEvents(aid)).map((event) => ({
        message: event,
        timestamp: event.attachments.FirstSeenReplayCouples[0]?.dt ?? new Date(0),
      }));
      if (events.length === 0) {
        log?.debug("GET /oobi: not found", { aid });
        response = new Response("Not Found", { status: 404 });
      } else {
        log?.debug("GET /oobi: serving events", { aid, count: events.length });
        response = createResponse(events);
      }
    }
    response.headers.set("Keri-Aid", witness.aid);
    return response;
  }

  async function handleMessageRequest(request: Request): Promise<Response> {
    const atc = request.headers.get("CESR-ATTACHMENT");
    if (!atc) {
      log?.warn("rejecting POST /: missing CESR-ATTACHMENT");
      return Response.json({ error: "Bad Request" }, { status: 400 });
    }

    const bodyText = await request.text();
    let count = 0;
    for await (const event of parse(bodyText + atc)) {
      witness.handleMessage(event);
      count++;
    }

    log?.debug("POST /: handled messages", { count });
    return new Response(null, { status: 200 });
  }

  return async function handler(request: Request): Promise<Response> {
    const { method } = request;
    const pathname = new URL(request.url).pathname;

    if (pathname === "/") {
      switch (method) {
        case "GET":
          return Response.json({ status: "OK" });
        case "POST": {
          return handleMessageRequest(request);
        }
        default:
          return new Response("Method Not Allowed", { status: 405 });
      }
    }

    if (pathname.startsWith("/oobi")) {
      switch (method) {
        case "GET":
          return handleOobiRequest(request);
        default:
          return new Response("Method Not Allowed", { status: 405 });
      }
    }

    if (pathname === "/receipts") {
      switch (method) {
        case "POST":
          return handleReceiptRequest(request);
        default:
          return new Response("Method Not Allowed", { status: 405 });
      }
    }

    return new Response("Not Found", { status: 404 });
  };
}
