import { type ReceiptEvent } from "./events/events.ts";
import { type LocationRecord } from "./events/event-store.ts";
import { parse, type Message } from "cesr";

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

  async getReceipt(message: Message): Promise<Message<ReceiptEvent>> {
    const url = new URL("/receipts", this.#location.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`Invalid protocol: ${url}`);
    }

    const response = await fetch(url, {
      method: "POST",
      body: JSON.stringify(message.body),
      headers: {
        "Content-Type": "application/cesr+json",
        "CESR-ATTACHMENT": message.attachments.text(),
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to send event: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      throw new Error(`Failed to send event: ${response.status} ${response.statusText}`);
    }

    for await (const incoming of parse(response.body)) {
      if (incoming.body.t === "rct" && incoming.body.d === message.body.d) {
        return incoming as Message<ReceiptEvent>;
      }
    }

    throw new Error(`Failed to get receipt for event: ${response.status} ${response.statusText}`);
  }

  async sendMessage(message: Message) {
    const url = new URL("/", this.#location.url);

    const response = await fetch(url, {
      method: "POST",
      body: JSON.stringify(message.body),
      headers: {
        "Content-Type": "application/cesr+json",
        "CESR-ATTACHMENT": message.attachments.text(),
        "CESR-DESTINATION": this.#location.eid,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to send event: ${response.status} ${response.statusText}`);
    }
  }
}
