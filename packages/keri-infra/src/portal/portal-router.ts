import { encodeText, type Message, parse } from "cesr";
import type { ExchangeEventBody, QueryEventBody } from "keri";
import { KeyEvent, TransactionEvent } from "keri";
import { KeriLogger, type Logger } from "../logging/main.ts";
import { createMailboxResponse, type MailboxReply, queryMailbox, storeForward } from "../mailbox/main.ts";
import type { Portal, PortalStorage } from "./portal.ts";

export interface PortalRouterOptions {
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

/**
 * The portal's CESR service front: enrollment, store-and-forward, polling,
 * OOBIs for itself and its enrolled users, and the intake dispatch KERIpy
 * expects of the location it posts to — including answering `tels`/`logs`
 * queries by depositing the requested events into the requester's mailbox
 * under `/replay`, the way KERIpy witnesses do.
 */
export function createRouter(
  portal: Portal,
  storage: PortalStorage,
  options: PortalRouterOptions = {},
): (request: Request) => Promise<Response> {
  const log = new KeriLogger(options.logger);

  /** Answer a `tels`/`logs` query by depositing the events into the requester's `/replay` mailbox. */
  function replay(message: Message<QueryEventBody>): void {
    const requester =
      message.attachments.TransLastIdxSigGroups[0]?.prefix ?? message.attachments.TransIdxSigGroups[0]?.prefix;
    if (!requester) {
      log.warn("dropping unsigned query", { route: message.body.r });
      return;
    }

    const q = message.body.q as { i?: string; ri?: string };
    const events: Message[] = [];

    if (message.body.r === "tels") {
      if (q.ri) {
        const vcp = storage.getRegistry(q.ri);
        if (vcp) {
          events.push(vcp);
        }
      }
      if (q.i) {
        events.push(...storage.getCredentialEvents(q.i));
      }
    } else if (q.i) {
      events.push(...storage.getKeyEvents(q.i));
    }

    log.debug("replaying", { route: message.body.r, events: events.length, requester });
    for (const event of events) {
      storage.saveMailboxEntry(requester, "replay", event);
    }
  }

  async function handleIntake(request: Request): Promise<Response> {
    const atc = request.headers.get("CESR-ATTACHMENT") ?? "";
    const stream = (await request.text()) + atc;

    let messages: Message[];
    try {
      messages = await Array.fromAsync(parse(stream));
    } catch (cause) {
      log.warn("could not parse intake", { error: cause instanceof Error ? cause.message : String(cause) });
      return Response.json({ error: "Could not parse the CESR stream" }, { status: 400 });
    }

    const replies: MailboxReply[] = [];
    let queried = false;

    for (const message of messages) {
      const body = message.body as { t?: string; r?: string };

      if (body.t === "exn" && body.r === "/fwd") {
        storeForward(storage, message as Message<ExchangeEventBody>, log);
      } else if (body.t === "qry" && body.r === "mbx") {
        queried = true;
        replies.push(...queryMailbox(storage, message as Message<QueryEventBody>, log));
      } else if (body.t === "qry" && (body.r === "tels" || body.r === "logs")) {
        replay(message as Message<QueryEventBody>);
      } else if (KeyEvent.isKeyEvent(message) || TransactionEvent.isTransactionEvent(message)) {
        // Unverified upsert, same policy as Controller ingest: these are the
        // KEL/TEL artifacts senders push at the portal so queries can be
        // answered later.
        storage.saveMessage(message);
      } else {
        log.debug("ignoring message", { t: body.t, r: body.r });
      }
    }

    log.debug("intake", { messages: messages.length, queried, replies: replies.length });
    return queried ? createMailboxResponse(replies) : new Response(null, { status: 204 });
  }

  // The `kli mailbox add` contract: multipart form with the controller's full
  // KEL and its signed /end/role/add naming this portal; a plain 200 means
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

    const result = await portal.enroll(kel, rpy);
    if (!result.ok) {
      log.warn("rejecting enrollment", { error: result.error });
      return Response.json({ error: result.error }, { status: 400 });
    }

    log.debug("enrolled", { aid: result.aid });
    return Response.json({ aid: result.aid });
  }

  function handleOobi(pathname: string): Response {
    const aid = pathname.split("/")[2];

    // The deployed worker serves the portal's own identity before reaching this
    // router; this covers the standalone composition.
    if (!aid || aid === portal.aid) {
      log.debug("GET /oobi: serving self", { count: portal.events.length });
      return createOobiResponse(
        portal.events.map((event) => event.message),
        portal.aid,
      );
    }

    const messages = portal.serveOobi(aid);
    if (!messages) {
      log.debug("GET /oobi: unknown aid", { aid });
      return new Response("Not Found", { status: 404 });
    }

    log.debug("GET /oobi: serving enrolled aid", { aid, count: messages.length });
    return createOobiResponse(messages, aid);
  }

  return async function handler(request: Request): Promise<Response> {
    const { method } = request;
    const pathname = new URL(request.url).pathname;

    if (pathname === "/") {
      // KERIpy's streaming senders PUT the whole stream inline; everything else
      // POSTs with detached attachments. Both are intake.
      if (method === "POST" || method === "PUT") {
        return handleIntake(request);
      }
      if (method === "GET") {
        return Response.json({ status: "OK" });
      }
      return new Response("Method Not Allowed", { status: 405 });
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
      return handleOobi(pathname);
    }

    return new Response("Not Found", { status: 404 });
  };
}
