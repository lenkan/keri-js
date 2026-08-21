import { encodeText, type Message, parse } from "cesr";

export interface MailboxMessage {
  /** The SSE `id:` field — the mailbox's per-(pre, topic) ordinal — when the response was an event stream. */
  id?: number;
  /** The SSE `event:` field — the topic path as queried (leading slash included). */
  topic?: string;
  message: Message;
}

const DEFAULT_IDLE_MS = 1000;

function readWithIdle(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  idleMs: number,
): Promise<ReadableStreamReadResult<Uint8Array> | "idle"> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve("idle"), idleMs);
    reader.read().then(
      (result) => {
        clearTimeout(timer);
        resolve(result);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/**
 * Parses SSE frames (`id:`/`event:`/`data:`, blank-line terminated) into
 * mailbox messages. The stream is read to the end; KERIpy holds the connection
 * open after its snapshot, so a quiet period of `idleMs` also ends the read —
 * cancelling mid-frame never drops a delivered message the way the previous
 * stop-after-first-chunk behavior did.
 */
async function parseEventStream(body: ReadableStream<Uint8Array>, idleMs: number): Promise<MailboxMessage[]> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  const entries: MailboxMessage[] = [];

  let buffer = "";
  let id: number | undefined;
  let topic: string | undefined;
  let data = "";

  async function endFrame(): Promise<void> {
    if (data) {
      for await (const message of parse(data)) {
        entries.push({ id, topic, message });
      }
    }
    id = undefined;
    topic = undefined;
    data = "";
  }

  async function handleLine(line: string): Promise<void> {
    if (line === "") {
      await endFrame();
    } else if (line.startsWith("id:")) {
      const value = Number(line.slice(3).trim());
      id = Number.isFinite(value) ? value : undefined;
    } else if (line.startsWith("event:")) {
      topic = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      data += line.slice(5).trimStart();
    }
    // `retry:` and comment lines are ignored.
  }

  while (true) {
    const result = await readWithIdle(reader, idleMs);

    if (result === "idle") {
      await reader.cancel();
      break;
    }
    if (result.done) {
      break;
    }

    buffer += decoder.decode(result.value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      await handleLine(line.replace(/\r$/, ""));
    }
  }

  await handleLine(buffer.replace(/\r$/, ""));
  await endFrame();
  return entries;
}

export interface MailboxClientOptions {
  /**
   * The AID of the mailbox controller.
   */
  id: string;

  /**
   * The URL of the mailbox server to send messages to.
   */
  url: string;

  /**
   * Optional fetch implementation to use for sending messages.
   * Defaults to the global `fetch` function.
   */
  fetch?: typeof globalThis.fetch;

  /** Quiet time after which a held-open SSE stream is considered drained. */
  idleMs?: number;
}

export class MailboxClient {
  readonly url: string;
  readonly id: string;
  readonly #fetch: typeof globalThis.fetch;
  readonly #idleMs: number;

  constructor(options: MailboxClientOptions) {
    this.url = options.url;
    this.id = options.id;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#idleMs = options.idleMs ?? DEFAULT_IDLE_MS;
  }

  async sendMessage(message: Message, signal?: AbortSignal): Promise<MailboxMessage[]> {
    const url = new URL("/", this.url);

    const body = JSON.stringify(message.body);
    const headers = {
      "Content-Type": "application/cesr+json",
      "CESR-ATTACHMENT": encodeText(message.attachments.frames()),
      "CESR-DESTINATION": this.id,
    };

    const response = await this.#fetch(url, {
      method: "POST",
      body,
      headers,
      signal,
    });

    if (!response.ok) {
      throw new Error(`Failed to send event: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      return [];
    }

    const contentType = response.headers.get("Content-Type");
    if (!contentType) {
      return [];
    }

    if (contentType === "text/event-stream") {
      return await parseEventStream(response.body, this.#idleMs);
    }

    if (contentType?.startsWith("application/json")) {
      return [];
    }

    return (await Array.fromAsync(parse(response.body))).map((incoming) => ({ message: incoming }));
  }
}
