import { encodeText, type Message, parse } from "cesr";
import { type KeyEventBody, type ReceiptEventBody, verifySignature } from "keri";

export class WitnessClient {
  #url: string;
  #fetch: typeof globalThis.fetch;

  constructor(url: string, fetch?: typeof globalThis.fetch) {
    this.#url = url;
    this.#fetch = fetch ?? globalThis.fetch;
  }

  async receipt(event: Message<KeyEventBody>): Promise<Message<ReceiptEventBody>> {
    const url = new URL("/receipts", this.#url);

    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`Invalid protocol: ${url}`);
    }

    const fetchResponse = await this.#fetch(url, {
      method: "POST",
      body: JSON.stringify(event.body),
      headers: {
        "Content-Type": "application/cesr+json",
        "CESR-ATTACHMENT": encodeText(event.attachments.frames()),
      },
    });

    if (!fetchResponse.ok || !fetchResponse.body) {
      throw new Error(`Failed to submit event to witness: ${fetchResponse.status} ${fetchResponse.statusText}`);
    }

    for await (const incoming of parse(fetchResponse.body)) {
      if (incoming.body.t === "rct" && incoming.body.d === event.body.d) {
        for (const couple of incoming.attachments.NonTransReceiptCouples) {
          const result = verifySignature(event.raw, couple.prefix, couple.sig);
          if (!result.ok) {
            throw new Error(`Invalid witness signature from ${couple.prefix}: ${result.error}`);
          }
        }

        return incoming as Message<ReceiptEventBody>;
      }
    }

    throw new Error(`No receipt returned from ${this.#url}`);
  }
}
