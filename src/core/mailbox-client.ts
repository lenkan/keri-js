import { encodeText, type Message, parse } from "#keri/cesr";

async function parseEventStream(body: ReadableStream<Uint8Array>): Promise<Message[]> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  const messages: Message[] = [];
  let buffer = "";

  async function flushLine(line: string): Promise<void> {
    if (line.startsWith("data: ")) {
      messages.push(...(await Array.fromAsync(parse(line.slice(6)))));
    }
  }

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      await flushLine(line);
    }

    // Long-poll SSE servers (e.g. KERIpy) keep the stream open after sending
    // a snapshot. Once we have at least one message, stop reading and return.
    if (messages.length > 0) {
      await reader.cancel();
      return messages;
    }
  }
  await flushLine(buffer);
  return messages;
}

export interface MailboxClientOptions {
  /**
   * The SAID of the mailbox controller.
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
}

export class MailboxClient {
  readonly url: string;
  readonly id: string;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: MailboxClientOptions) {
    this.url = options.url;
    this.id = options.id;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async sendMessage(message: Message, signal?: AbortSignal): Promise<Message[]> {
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
      return await parseEventStream(response.body);
    }

    if (contentType?.startsWith("application/json")) {
      return [];
    }

    return await Array.fromAsync(parse(response.body));
  }
}
