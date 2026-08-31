import { Attachments, type Message, parse } from "../cesr/main.ts";
import type { KeyEventBody } from "../main.ts";
import { type Logger, logger } from "./logger.ts";
import { encodeMessage } from "./message-codec.ts";
import { createMailboxResponse } from "./sse.ts";
import type { MailboxReply, Witness, WitnessEvent } from "./witness.ts";
import { WitnessError } from "./witness-error.ts";

export interface RouterOptions {
  logger?: Logger;
}

/**
 * `trailing` messages are appended with their attachments untouched. Key events
 * get a rebuilt attachment set carrying `FirstSeenReplayCouples`, but a signed
 * `rpy` is endorsed into a `TransIdxSigGroup` that rebuild would drop, taking
 * the signature with it.
 */
function createResponse(events: readonly WitnessEvent[], trailing: readonly Message[] = []): Response {
  const body = events
    .map(({ message, timestamp }) => {
      const atc = new Attachments({
        ControllerIdxSigs: message.attachments.ControllerIdxSigs,
        WitnessIdxSigs: message.attachments.WitnessIdxSigs,
        NonTransReceiptCouples: message.attachments.NonTransReceiptCouples,
        FirstSeenReplayCouples: [{ fnu: String((message.body as KeyEventBody).s ?? "0"), dt: timestamp }],
      });
      return encodeMessage(message, atc);
    })
    .concat(trailing.map((message) => encodeMessage(message)))
    .join("");

  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/json+cesr" },
  });
}

/**
 * Names who the OOBI is *about*. KERIpy prefers this header over the AID in the
 * URL and binds the contact alias to it, so answering a controller's OOBI with
 * the witness's own AID makes the resolver treat the controller as the witness
 * — and peer traffic then goes to the witness's controller endpoint instead of
 * into the controller's mailbox.
 */
function withSubject(response: Response, aid: string): Response {
  response.headers.set("Keri-Aid", aid);
  return response;
}

export function createRouter(witness: Witness, options: RouterOptions = {}): (request: Request) => Promise<Response> {
  const log = logger(options.logger);

  /** The body and its detached attachments as one CESR stream, or null with the 400 already logged. */
  async function readStream(request: Request, route: string): Promise<string | null> {
    const atc = request.headers.get("CESR-ATTACHMENT");
    if (!atc) {
      log.warn(`rejecting ${route}: missing CESR-ATTACHMENT`);
      return null;
    }
    return (await request.text()) + atc;
  }

  async function handleReceiptRequest(request: Request): Promise<Response> {
    const stream = await readStream(request, "POST /receipts");
    if (stream === null) {
      return Response.json({ error: "Bad Request" }, { status: 400 });
    }

    const receipts: WitnessEvent[] = [];

    for await (const witnessEvent of parse(stream)) {
      try {
        const receipt = await witness.receipt(witnessEvent as Message<KeyEventBody>);
        receipts.push({ message: receipt, timestamp: new Date() });
      } catch (err) {
        if (err instanceof WitnessError) {
          log.warn("rejecting POST /receipts", { error: err.message });
          return Response.json({ error: "Bad Request" }, { status: 400 });
        }
        throw err;
      }
    }

    log.debug("POST /receipts: issued receipts", { count: receipts.length });
    return createResponse(receipts);
  }

  async function handleOobiRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const aid = url.pathname.split("/")[2];

    if (aid === undefined || aid === witness.aid) {
      log.debug("GET /oobi: serving self", { count: witness.events.length });
      return withSubject(createResponse(witness.events), witness.aid);
    }

    const events = (await Array.fromAsync(witness.getKeyEvents(aid))).map((event) => ({
      message: event,
      timestamp: event.attachments.FirstSeenReplayCouples[0]?.dt ?? new Date(0),
    }));

    if (events.length === 0) {
      log.debug("GET /oobi: not found", { aid });
      return new Response("Not Found", { status: 404 });
    }

    // KERIpy's emit order: the KEL, then this witness's location, then the
    // role that points at it. The location is pointless without the role.
    const role = await witness.mailboxRole(aid);
    const trailing = role ? [...witness.location, role] : [];
    log.debug("GET /oobi: serving events", { aid, count: events.length, mailbox: role !== null });
    return withSubject(createResponse(events, trailing), aid);
  }

  async function handleMessageRequest(request: Request): Promise<Response> {
    const stream = await readStream(request, "POST /");
    if (stream === null) {
      return Response.json({ error: "Bad Request" }, { status: 400 });
    }

    const replies: MailboxReply[] = [];
    let count = 0;
    let queried = false;

    for await (const event of parse(stream)) {
      const { t, r } = event.body as { t?: string; r?: string };
      queried ||= t === "qry" && r === "mbx";
      replies.push(...(await witness.handleMessage(event)));
      count++;
    }

    // A poll answers with the SSE snapshot even when it is empty — a 204 is how
    // KERIpy learns there is nothing new. Plain intake keeps its bare 200.
    if (queried) {
      log.debug("POST /: answered mailbox query", { count, replies: replies.length });
      return createMailboxResponse(replies);
    }

    log.debug("POST /: handled messages", { count });
    return new Response(null, { status: 200 });
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
