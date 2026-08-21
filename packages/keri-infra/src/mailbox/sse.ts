import { encodeText } from "cesr";
import type { MailboxReply } from "./mailbox.ts";

const RETRY_MS = 5000;

export function encodeReply(reply: MailboxReply): string {
  // Attachments pass through whole — a replayed vcp/iss travels on its
  // SealSourceCouples, which a signature-only whitelist would strip. An empty
  // group is omitted entirely: KERIpy rejects a zero-size `-VAA` as a parse
  // error and drops the message with it.
  const frames = reply.message.attachments.frames();
  const atc = frames.length > 1 ? encodeText(frames) : "";
  const cesr = new TextDecoder().decode(reply.message.raw) + atc;
  return `id: ${reply.id}\nevent: ${reply.topic}\nretry: ${RETRY_MS}\ndata: ${cesr}\n\n`;
}

export function createMailboxResponse(replies: readonly MailboxReply[]): Response {
  if (replies.length === 0) {
    return new Response(null, { status: 204 });
  }

  const body = new TextEncoder().encode(replies.map(encodeReply).join(""));

  // A stream body, not a string: a string would get a Content-Length, and
  // hio's HTTP client only feeds its SSE parser on chunked or unknown-length
  // responses — KERIpy silently ignores a Content-Length event stream.
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(body);
      controller.close();
    },
  });

  return new Response(stream, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
}
