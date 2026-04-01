import { type ParseInput, parse } from "../cesr/__main__.ts";
import type { WitnessEvent } from "./witness.ts";

export async function* parseKeyEvents(input: ParseInput): AsyncIterableIterator<WitnessEvent> {
  for await (const message of parse(input)) {
    yield { message, timestamp: new Date() };
  }
}
