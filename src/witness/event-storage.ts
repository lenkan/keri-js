import type { WitnessEvent } from "./witness.ts";

export interface ListEventArgs {
  i: string;
}

export interface EventStorage {
  saveEvent(event: WitnessEvent): Promise<void>;
  listEvents(args: ListEventArgs): Promise<WitnessEvent[]>;
}
