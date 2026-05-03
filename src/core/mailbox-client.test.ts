import assert from "node:assert";
import { basename } from "node:path";
import { describe, test } from "node:test";
import { encodeText, type Message } from "#keri/cesr";
import { incept } from "./key-event.ts";
import { generateKeyPair } from "./keys.ts";
import { MailboxClient } from "./mailbox-client.ts";

function makeMessage(): Message {
  const { publicKey } = generateKeyPair();
  return incept({ signingKeys: [publicKey], nextKeys: [] });
}

function encodeMessage(message: Message): string {
  return new TextDecoder().decode(message.raw) + encodeText(message.attachments.frames());
}

function streamFromChunks(chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const c of chunks) controller.enqueue(encoder.encode(c));
      controller.close();
    },
  });
}

function sseFrame(message: Message, opts: { id?: number; event?: string } = {}): string {
  const lines: string[] = [];
  if (opts.id !== undefined) {
    lines.push(`id: ${opts.id}`);
  }
  if (opts.event !== undefined) {
    lines.push(`event: ${opts.event}`);
  }
  lines.push("retry: 5000");
  lines.push(`data: ${encodeMessage(message)}`);
  return `${lines.join("\n")}\n\n`;
}

function eventStreamResponse(body: ReadableStream<Uint8Array>): Response {
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
}

describe(basename(import.meta.url), () => {
  describe("sendMessage()", () => {
    test("should POST to / with correct headers and body", async () => {
      const message = makeMessage();
      let captured: Request | undefined;
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async (input, init) => {
          captured = new Request(input, init);
          return new Response(null, { status: 204 });
        },
      });

      await client.sendMessage(message);

      assert.ok(captured);
      assert.strictEqual(captured.method, "POST");
      assert.strictEqual(new URL(captured.url).pathname, "/");
      assert.strictEqual(captured.headers.get("Content-Type"), "application/cesr+json");
      assert.strictEqual(captured.headers.get("CESR-DESTINATION"), "EAID");
      assert.ok(captured.headers.get("CESR-ATTACHMENT") !== null);
      assert.strictEqual(await captured.text(), JSON.stringify(message.body));
    });

    test("should forward AbortSignal to fetch", async () => {
      const controller = new AbortController();
      let capturedSignal: AbortSignal | null | undefined;
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async (_, init) => {
          capturedSignal = init?.signal;
          return new Response(null, { status: 204 });
        },
      });

      await client.sendMessage(makeMessage(), controller.signal);
      assert.strictEqual(capturedSignal, controller.signal);
    });

    test("should throw when response is not ok", async () => {
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => new Response("nope", { status: 500, statusText: "Server Error" }),
      });
      await assert.rejects(client.sendMessage(makeMessage()), /500/);
    });

    test("should return [] for 204 No Content", async () => {
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => new Response(null, { status: 204 }),
      });
      assert.deepStrictEqual(await client.sendMessage(makeMessage()), []);
    });

    test("should return [] for application/json response", async () => {
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => Response.json({ ok: true }),
      });
      assert.deepStrictEqual(await client.sendMessage(makeMessage()), []);
    });

    test("should parse single SSE message", async () => {
      const reply = makeMessage();
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => eventStreamResponse(streamFromChunks([sseFrame(reply, { id: 1, event: "/credential" })])),
      });

      const messages = await client.sendMessage(makeMessage());
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].body.t, "icp");
      assert.strictEqual(messages[0].body.i, reply.body.i);
    });

    test("should parse multiple SSE messages in one chunk", async () => {
      const a = makeMessage();
      const b = makeMessage();
      const body = sseFrame(a, { id: 1 }) + sseFrame(b, { id: 2 });
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => eventStreamResponse(streamFromChunks([body])),
      });

      const messages = await client.sendMessage(makeMessage());
      assert.strictEqual(messages.length, 2);
      assert.strictEqual(messages[0].body.i, a.body.i);
      assert.strictEqual(messages[1].body.i, b.body.i);
    });

    test("should reassemble a data line split across chunks", async () => {
      const reply = makeMessage();
      const frame = sseFrame(reply, { id: 1 });
      // Split mid-data so the parser must buffer across reads
      const splitAt = frame.indexOf("data: ") + 10;
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => eventStreamResponse(streamFromChunks([frame.slice(0, splitAt), frame.slice(splitAt)])),
      });

      const messages = await client.sendMessage(makeMessage());
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].body.i, reply.body.i);
    });

    test("should reassemble a data line split across many small chunks", async () => {
      const reply = makeMessage();
      const frame = sseFrame(reply, { id: 1 });
      const chunks: string[] = [];
      for (let i = 0; i < frame.length; i += 7) {
        chunks.push(frame.slice(i, i + 7));
      }
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => eventStreamResponse(streamFromChunks(chunks)),
      });

      const messages = await client.sendMessage(makeMessage());
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].body.i, reply.body.i);
    });

    test("should return without waiting for stream to close once a message is parsed", async () => {
      const reply = makeMessage();
      let cancelled = false;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(sseFrame(reply, { id: 1 })));
          // Server keeps the stream open (long-poll); never call controller.close()
        },
        cancel() {
          cancelled = true;
        },
      });

      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => eventStreamResponse(stream),
      });

      const messages = await client.sendMessage(makeMessage());
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].body.i, reply.body.i);
      assert.strictEqual(cancelled, true);
    });

    test("should parse a final data line that has no trailing newline", async () => {
      const reply = makeMessage();
      // Drop the trailing "\n\n" — common when a server flushes early
      const frame = `data: ${encodeMessage(reply)}`;
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => eventStreamResponse(streamFromChunks([frame])),
      });

      const messages = await client.sendMessage(makeMessage());
      assert.strictEqual(messages.length, 1);
      assert.strictEqual(messages[0].body.i, reply.body.i);
    });

    test("should ignore non-data SSE lines (id, event, retry, comments)", async () => {
      const body = ["id: 1", "event: /credential", "retry: 5000", ": comment", "", ""].join("\n");
      const client = new MailboxClient({
        id: "EAID",
        url: "http://mailbox.example",
        fetch: async () => eventStreamResponse(streamFromChunks([body])),
      });

      const messages = await client.sendMessage(makeMessage());
      assert.strictEqual(messages.length, 0);
    });
  });
});
