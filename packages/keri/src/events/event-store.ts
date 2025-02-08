import type { KeyEvent } from "./main.ts";

export interface KeyEventMessage<T extends KeyEvent = KeyEvent> {
  event: T;
  attachments: KeyEventAttachment[];
}

export interface ListArgs {
  i?: string;
  d?: string;
  t?: string;
  r?: string;
}

export interface KeyEventAttachment {
  code: string;
  value: string;
}

export interface EventStore {
  list(args?: ListArgs): Promise<KeyEventMessage[]>;
  saveEvent(event: KeyEvent): Promise<void>;
  saveAttachment(eventId: string, attachment: KeyEventAttachment): Promise<void>;
}

export class MemoryEventStore implements EventStore {
  #events = new Map<string, KeyEventMessage>();

  async list(args?: ListArgs): Promise<KeyEventMessage[]> {
    return Array.from(this.#events.values()).filter((event) => {
      if (!args || Object.keys(args).length === 0) {
        return true;
      }

      const match = Object.entries(args).every(([key, value]) => {
        return key in event.event && event.event[key] === value;
      });

      return match;
    });
  }

  async saveEvent(event: KeyEvent): Promise<void> {
    if (!this.#events.has(event.d)) {
      this.#events.set(event.d, { event, attachments: [] });
    }
  }

  async saveAttachment(eventId: string, attachment: KeyEventAttachment): Promise<void> {
    const event = this.#events.get(eventId);
    if (!event) {
      throw new Error("No such event");
    }

    event.attachments.push(attachment);
  }
}
