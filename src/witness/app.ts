import { Hono } from "hono";
import { Attachments, Message } from "../cesr/__main__.ts";
import type { KeyEventBody } from "../core/main.ts";
import type { EventStorage } from "./event-storage.ts";
import { parseKeyEvents } from "./parser.ts";
import type { Witness, WitnessEvent } from "./witness.ts";

export interface WitnessOptions {
  witness: Witness;
  storage: EventStorage;
  logger?: (message: string, context: Record<string, unknown>) => void;
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
      return [new TextDecoder().decode(message.raw), atc.text()];
    })
    .join("");

  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json+cesr" },
  });
}

export function createApp(options: WitnessOptions) {
  const { witness } = options;
  const app = new Hono();

  app.get("/", (c) => c.json({ message: "OK" }));

  app.use(async (c, next) => {
    const start = Date.now();
    try {
      await next();
    } finally {
      const ms = Date.now() - start;
      options.logger?.(`${c.req.method} ${c.req.url} - ${c.res.status} - ${ms}ms`, {
        request: {
          url: c.req.url,
          method: c.req.method,
          headers: c.req.header(),
        },
        response: {
          status: c.res.status,
          headers: Object.fromEntries(c.res.headers),
        },
      });
    }
  });

  app.get("/oobi", () => {
    const response = createResponse(options.witness.events);
    response.headers.set("Keri-Aid", options.witness.aid);
    return response;
  });

  app.get(`/oobi/${witness.aid}`, () => {
    return createResponse(witness.events);
  });

  app.get("/oobi/:aid/:role?/:eid?", async (c) => {
    const aid = c.req.param("aid");
    const events = await options.storage.listEvents({ i: aid });

    if (events.length === 0) {
      return c.notFound();
    }

    return createResponse(events);
  });

  app.post("/receipts", async (c) => {
    const atc = c.req.header("CESR-ATTACHMENT");
    if (!atc) {
      return Response.json({ error: "Bad Request" }, { status: 400 });
    }

    const bodyText = await c.req.text();

    const receipts: WitnessEvent[] = [];

    for await (const witnessEvent of parseKeyEvents(bodyText + atc)) {
      const body = witnessEvent.message.body as KeyEventBody;

      if (typeof body.i !== "string" || typeof body.d !== "string" || typeof body.s !== "string") {
        return Response.json({ error: "Bad Request" }, { status: 400 });
      }

      if (witnessEvent.message.attachments.ControllerIdxSigs.length === 0) {
        return Response.json({ error: "Bad Request" }, { status: 400 });
      }

      const receipt = witness.endorse(witnessEvent.message as Message<KeyEventBody>);
      receipts.push({ message: receipt, timestamp: new Date() });

      const storedMessage = new Message(witnessEvent.message.body, {
        ControllerIdxSigs: witnessEvent.message.attachments.ControllerIdxSigs,
        NonTransReceiptCouples: [
          ...witnessEvent.message.attachments.NonTransReceiptCouples,
          ...receipt.attachments.NonTransReceiptCouples,
        ],
      });
      await options.storage.saveEvent({ message: storedMessage, timestamp: witnessEvent.timestamp });
    }

    return createResponse(receipts);
  });

  return app;
}
