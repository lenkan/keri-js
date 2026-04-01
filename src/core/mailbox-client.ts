import { type Message, parse } from "../cesr/__main__.ts";

export interface MailboxClientOptions {
  /**
   * The SAID of the mailbox controller.
   */
  id: string;

  /**
   * The URL of the mailbox server to send messages to.
   */
  url: string;
}

export class MailboxClient {
  readonly url: string;
  readonly id: string;

  constructor(options: MailboxClientOptions) {
    this.url = options.url;
    this.id = options.id;
  }

  async sendMessage(message: Message, signal?: AbortSignal): Promise<Message[]> {
    const url = new URL("/", this.url);

    const body = JSON.stringify(message.body);
    const headers = {
      "Content-Type": "application/cesr+json",
      "CESR-ATTACHMENT": message.attachments.text(),
      "CESR-DESTINATION": this.id,
    };

    const response = await fetch(url, {
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
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          break;
        }

        const str = new TextDecoder().decode(value);

        for (const line of str.split("\n")) {
          if (line.startsWith("data: ")) {
            const data = line.slice(6);
            const message = await Array.fromAsync(parse(data));
            reader.cancel("Got message, cancelling reader");
            return message;
          }
        }
      }
    }

    if (contentType?.startsWith("application/json")) {
      return [];
    }

    return await Array.fromAsync(parse(response.body));
  }
}
