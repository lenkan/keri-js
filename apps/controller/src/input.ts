import { createReadStream } from "node:fs";

export async function* resolveInputStream(input: string): AsyncIterableIterator<Uint8Array> {
  if (input === "-") {
    yield* process.stdin;
    return;
  }

  if (input.startsWith("http://") || input.startsWith("https://")) {
    const response = await fetch(input);
    if (response.body) {
      yield* response.body;
    }

    return;
  }

  yield* createReadStream(input);
}
