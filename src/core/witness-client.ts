import { Matter, type Message, parse } from "../cesr/__main__.ts";
import type { KeyEventBody } from "./key-event.ts";
import type { ReceiptEvent } from "./receipt-event.ts";
import { verifySignature } from "./verify.ts";

export class WitnessClient {
  #url: string;
  #fetch: typeof globalThis.fetch;

  constructor(url: string, fetch?: typeof globalThis.fetch) {
    this.#url = url;
    this.#fetch = fetch ?? globalThis.fetch;
  }

  async receipt(event: Message<KeyEventBody>): Promise<ReceiptEvent> {
    const url = new URL("/receipts", this.#url);

    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`Invalid protocol: ${url}`);
    }

    const fetchResponse = await this.#fetch(url, {
      method: "POST",
      body: JSON.stringify(event.body),
      headers: {
        "Content-Type": "application/cesr+json",
        "CESR-ATTACHMENT": event.attachments.text(),
      },
    });

    if (!fetchResponse.ok || !fetchResponse.body) {
      throw new Error(`Failed to submit event to witness: ${fetchResponse.status} ${fetchResponse.statusText}`);
    }

    for await (const incoming of parse(fetchResponse.body)) {
      if (incoming.body.t === "rct" && incoming.body.d === event.body.d) {
        for (const couple of incoming.attachments.NonTransReceiptCouples) {
          if (!verifySignature(event.raw, Matter.parse(couple.prefix), Matter.parse(couple.sig).raw)) {
            throw new Error(`Invalid witness signature from ${couple.prefix}`);
          }
        }

        return incoming as ReceiptEvent;
      }
    }

    throw new Error(`No receipt returned from ${this.#url}`);
  }
}
