import { encodeText, type Message, parse } from "cesr";
import type { ExchangeEventBody, QueryEventBody } from "keri";
import { KeyEvent, TransactionEvent } from "keri";
import { KeriLogger, type Logger } from "../logging/main.ts";
import {
  createMailboxResponse,
  createMailboxRouter,
  type Mailbox,
  type MailboxReply,
  queryMailbox,
  storeForward,
} from "../mailbox/main.ts";
import type { CredentialStorage, KeyEventStorage, MailboxServerStorage } from "../storage/main.ts";
import { createRouter as createWitnessRouter, type Witness } from "../witness/main.ts";

export type PortalStorage = MailboxServerStorage & KeyEventStorage & CredentialStorage;

export interface PortalRouterOptions {
  logger?: Logger;
}

/**
 * One CESR service front for a portal identity: the mailbox face (enrollment,
 * store-and-forward, polling, enrolled-AID OOBIs), the witness face (receipts
 * only), and the intake dispatch KERIpy expects of the location it posts to —
 * including answering `tels`/`logs` queries by depositing the requested events
 * into the requester's mailbox under `/replay`, the way KERIpy witnesses do.
 */
export function createRouter(
  mailbox: Mailbox,
  witness: Witness,
  storage: PortalStorage,
  options: PortalRouterOptions = {},
): (request: Request) => Promise<Response> {
  const log = new KeriLogger(options.logger);
  const mailboxRouter = createMailboxRouter(mailbox, options);
  const witnessRouter = createWitnessRouter(witness, options);

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
      } else if (body.t === "rct") {
        witness.handleMessage(message);
      } else if (KeyEvent.isKeyEvent(message) || TransactionEvent.isTransactionEvent(message)) {
        // Unverified upsert, same policy as Controller ingest: these are the
        // KEL/TEL artifacts senders push at their witness so queries can be
        // answered later.
        storage.saveMessage(message);
      } else {
        log.debug("ignoring message", { t: body.t, r: body.r });
      }
    }

    log.debug("intake", { messages: messages.length, queried, replies: replies.length });
    return queried ? createMailboxResponse(replies) : new Response(null, { status: 204 });
  }

  return async function handler(request: Request): Promise<Response> {
    const pathname = new URL(request.url).pathname;

    if (pathname === "/receipts") {
      return witnessRouter(request);
    }
    // KERIpy's streaming senders PUT the whole stream inline; everything else
    // POSTs with detached attachments. Both are intake.
    if (pathname === "/" && (request.method === "POST" || request.method === "PUT")) {
      return handleIntake(request);
    }

    // The self OOBI comes from the witness face: its events advertise the
    // `controller` role, which is what makes senders deliver direct and lets
    // witness clients resolve the receipting endpoint. (The deployed worker
    // serves its own identity before reaching this router; this covers the
    // standalone composition.)
    if (request.method === "GET" && pathname.startsWith("/oobi")) {
      const aid = pathname.split("/")[2];
      if (!aid || aid === witness.aid) {
        const body = witness.events
          .flatMap(({ message }) => [new TextDecoder().decode(message.raw), encodeText(message.attachments.frames())])
          .join("");
        return new Response(body, {
          status: 200,
          headers: { "Content-Type": "application/json+cesr", "Keri-Aid": witness.aid },
        });
      }
    }

    return mailboxRouter(request);
  };
}
