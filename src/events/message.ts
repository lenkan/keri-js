import { Parser } from "cesr/__unstable__";
import { type KeyEvent } from "./events.ts";
import { Attachments, type AttachmentsInit } from "./attachments.ts";

export class KeyEventMessage<T extends KeyEvent = KeyEvent> {
  readonly event: T;
  readonly #attachments: Attachments;

  constructor(event: T, init?: AttachmentsInit) {
    this.event = event;
    this.#attachments = new Attachments(init);
  }

  get raw(): Uint8Array {
    return new TextEncoder().encode(JSON.stringify(this.event));
  }

  get attachments(): Attachments {
    return this.#attachments;
  }

  serialize(): string {
    return JSON.stringify(this.event) + this.#attachments.toString();
  }

  static parse(attachments: string): KeyEventMessage {
    return this.fromData(new TextEncoder().encode(attachments));
  }

  static fromData(data: Uint8Array): KeyEventMessage {
    const parser = new Parser();
    const iterator = parser.parse(data);
    const result = iterator.next();

    if (result.done) {
      throw new Error("No data to parse");
    }

    if (result.value.type !== "message") {
      throw new Error("Expected message frame");
    }

    const payload = JSON.parse(result.value.text) as KeyEvent;
    // TODO: Should not parse twice
    return new KeyEventMessage(payload, Attachments.fromData(data));
  }
}
