import type { KeyEvent } from "../events/main.ts";

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
