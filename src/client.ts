import { cesr, CountCode_10, type Counter } from "cesr/__unstable__";
import { parse } from "cesr";
import { type KeyEvent, type ReceiptEvent } from "./events/events.ts";
import { type KeyEventMessage, type LocationRecord } from "./events/event-store.ts";

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

  async getReceipt(message: Message): Promise<KeyEventMessage<ReceiptEvent>> {
    const url = new URL("/receipts", this.#location.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`Invalid protocol: ${url}`);
    }

    const response = await fetch(url, {
      method: "POST",
      body: JSON.stringify(message.event),
      headers: {
        "Content-Type": "application/cesr+json",
        "CESR-ATTACHMENT": message.attachment,
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

  async sendMessage(message: Message) {
    const url = new URL("/", this.#location.url);

    const response = await fetch(url, {
      method: "POST",
      body: JSON.stringify(message.event),
      headers: {
        "Content-Type": "application/cesr+json",
        "CESR-ATTACHMENT": message.attachment,
        "CESR-DESTINATION": this.#location.eid,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to send event: ${response.status} ${response.statusText}`);
    }
  }
}

export async function* parseKeyEvents(input: ReadableStream<Uint8Array>): AsyncIterableIterator<KeyEventMessage> {
  for await (const message of parse(input)) {
    const signatures: string[] = [];
    const receipts: string[] = [];

    let group: Counter | null = null;

    for (const attachment of message.attachments) {
      if (attachment.startsWith("-")) {
        group = cesr.decodeCounter(attachment);
      } else if (group) {
        switch (group.code) {
          case CountCode_10.ControllerIdxSigs:
            signatures.push(attachment);
            break;
          case CountCode_10.NonTransReceiptCouples:
            receipts.push(attachment);
            break;
        }
      }
    }

    yield {
      event: message.payload as KeyEvent,
      receipts: decouple(receipts).map(([backer, signature]) => ({ backer, signature })),
      signatures,
      timestamp: new Date(),
    };
  }
}

function decouple<T>(arr: T[]): [T, T][] {
  const result: [T, T][] = [];

  for (let i = 0; i < arr.length; i++) {
    if (i % 2 === 0) {
      result.push([arr[i], arr[i + 1]]);
    }
  }

  return result;
}
