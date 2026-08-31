import { encodeUtf8 } from "../cesr/main.ts";
import { encodeMessage } from "./message-codec.ts";
import type { MailboxReply } from "./witness.ts";

const RETRY_MS = 5000;

function encodeReply(reply: MailboxReply): string {
  // Attachments pass through whole — a replayed vcp/iss travels on its
  // SealSourceCouples, which a signature-only whitelist would strip.
  const cesr = encodeMessage(reply.message);
  return `id: ${reply.id}\nevent: ${reply.topic}\nretry: ${RETRY_MS}\ndata: ${cesr}\n\n`;
}

export function createMailboxResponse(replies: readonly MailboxReply[]): Response {
  if (replies.length === 0) {
    return new Response(null, { status: 204 });
  }

  const body = encodeUtf8(replies.map(encodeReply).join(""));

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
