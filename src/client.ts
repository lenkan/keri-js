import { parse } from "cesr";
import { type KeyEvent, type ReceiptEvent } from "./events/events.ts";
import { type LocationRecord } from "./events/event-store.ts";
import { KeyEventMessage } from "./events/message.ts";
import { Attachments } from "./events/attachments.ts";

export interface Message {
  event: KeyEvent;
  attachment: string;
}

export interface SendArgs {
  messages: Message[];
}

export interface ClientOptions {
  role: string;
  endpoint: LocationRecord;
}

export class Client {
  #location: LocationRecord;
  role: string;

  constructor(options: ClientOptions) {
    this.#location = options.endpoint;
    this.role = options.role;
  }

  async getReceipt(message: KeyEventMessage): Promise<KeyEventMessage<ReceiptEvent>> {
    const url = new URL("/receipts", this.#location.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`Invalid protocol: ${url}`);
    }

    const response = await fetch(url, {
      method: "POST",
      body: message.raw,
      headers: {
        "Content-Type": "application/cesr+json",
        "CESR-ATTACHMENT": message.attachments.toString(),
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to send event: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      throw new Error(`Failed to send event: ${response.status} ${response.statusText}`);
    }

    for await (const event of parseKeyEvents(response.body)) {
      if (event.event.t === "rct" && event.event.d === message.event.d) {
        return event as KeyEventMessage<ReceiptEvent>;
      }
    }

    throw new Error(`Failed to get receipt for event: ${response.status} ${response.statusText}`);
  }

  async sendMessage(message: KeyEventMessage) {
    const url = new URL("/", this.#location.url);

    const response = await fetch(url, {
      method: "POST",
      body: message.raw,
      headers: {
        "Content-Type": "application/cesr+json",
        "CESR-ATTACHMENT": message.attachments.toString(),
        "CESR-DESTINATION": this.#location.eid,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to send event: ${response.status} ${response.statusText}`);
    }
  }
}

export async function* parseKeyEvents(input: ReadableStream<Uint8Array>): AsyncIterableIterator<KeyEventMessage> {
  for await (const frame of parse(input)) {
    yield new KeyEventMessage(frame.payload as KeyEvent, Attachments.parse(frame.attachments.join("")));
  }
}
