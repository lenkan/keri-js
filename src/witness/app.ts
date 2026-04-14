import { Hono } from "hono";
import { Attachments } from "../cesr/__main__.ts";
import type { KeyEventBody } from "../core/main.ts";
import { parseKeyEvents } from "./parser.ts";
import { type Witness, WitnessError, type WitnessEvent } from "./witness.ts";

export interface WitnessOptions {
  witness: Witness;
  logger?: (message: string, context: Record<string, unknown>) => void;
}

/** @deprecated Use WitnessOptions */
export type AppOptions = WitnessOptions;

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

export function createApp(options: WitnessOptions): Hono {
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
    const response = createResponse(witness.events);
    response.headers.set("Keri-Aid", witness.aid);
    return response;
  });

  app.get(`/oobi/${witness.aid}`, () => {
    return createResponse(witness.events);
  });

  app.get("/oobi/:aid/:role?/:eid?", (c) => {
    const aid = c.req.param("aid");
    const events = Array.from(witness.getKeyEvents(aid)).map((event) => ({
      message: event,
      timestamp: event.attachments.FirstSeenReplayCouples[0]?.dt ?? new Date(0),
    }));

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
      try {
        const receipt = witness.receive(witnessEvent.message as Parameters<Witness["receive"]>[0]);
        receipts.push({ message: receipt, timestamp: new Date() });
      } catch (err) {
        if (err instanceof WitnessError) {
          return Response.json({ error: "Bad Request" }, { status: 400 });
        }
        throw err;
      }
    }

    return createResponse(receipts);
  });

  return app;
}
