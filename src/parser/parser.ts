import { parseVersion } from "./version.ts";
import { decodeBase64Int } from "./base64.ts";
import { CounterCode, CounterCodeTable, IndexerCodeTable, MatterCodeTable } from "./codes.ts";
import type { KeyEvent } from "../events/main.ts";

interface CountContext {
  code: keyof typeof CounterCodeTable;
  count: number;
}

function concat(a: Uint8Array, b: Uint8Array) {
  if (a.length === 0) {
    return b;
  }

  if (b.length === 0) {
    return a;
  }

  const merged = new Uint8Array(a.length + b.length);
  merged.set(a);
  merged.set(b, a.length);
  return merged;
}

export class Parser {
  #decoder = new TextDecoder();
  #countContext: CountContext;
  #stream: AsyncIterableIterator<Uint8Array<ArrayBufferLike>>;
  #buffer: Uint8Array | null;

  constructor(stream: AsyncIterableIterator<Uint8Array>) {
    this.#stream = stream;
  }

  async #readBytes(size: number): Promise<Uint8Array | null> {
    if (typeof size !== "number") {
      throw new Error(`Size must be a number, got '${size}'`);
    }

    while (!this.#buffer || this.#buffer.length < size) {
      const result = await this.#stream.next();

      if (result.done) {
        return null;
      }

      this.#buffer = concat(this.#buffer ?? new Uint8Array(0), result.value);
    }

    const chunk = this.#buffer.slice(0, size);
    this.#buffer = this.#buffer.slice(size);
    return chunk;
  }

  async #readCharacters(count: number): Promise<string> {
    const chunk = await this.#readBytes(count);
    return this.#decoder.decode(chunk);
  }

  async readOne(): Promise<string | null> {
    let code = "";

    while (code.length < 4) {
      const next = await this.#readBytes(1);
      if (next === null) {
        return null;
      }

      code += this.#decoder.decode(next);

      if (code === "{") {
        const prefix = code + (await this.#readCharacters(22));
        const version = parseVersion(prefix);
        return prefix + (await this.#readCharacters(version.size - prefix.length));
      }

      if (code.startsWith("-") && code in CounterCodeTable) {
        const size = CounterCodeTable[code];
        if (size && size.fs !== null) {
          const qb64 = await this.#readCharacters(size.fs - size.hs);
          const count = decodeBase64Int(qb64);

          if (code === CounterCode.AttachmentGroup || code === CounterCode.BigAttachmentGroup) {
            // Attachment group, currently no need to keep track of the count
          } else {
            // Stores the counter and expected count so we know what to expect next
            this.#countContext = {
              code,
              count,
            };
          }

          return code + qb64;
        } else if (!size || size.fs === null) {
          throw new Error(`Variable length currently not supported code=${code}`);
        }
      } else if (
        this.#countContext &&
        this.#countContext.count > 0 &&
        [
          CounterCode.ControllerIdxSigs,
          CounterCode.WitnessIdxSigs,
          CounterCode.TransIdxSigGroups,
          CounterCode.TransLastIdxSigGroups,
        ].includes(this.#countContext.code)
      ) {
        if (code in IndexerCodeTable) {
          const size = IndexerCodeTable[code];

          if (size && size.fs) {
            this.#countContext.count--;
            const qb64 = await this.#readCharacters(size.fs - size.hs);
            return code + qb64;
          } else if (size) {
            throw new Error(`Variable length currently not supported code=${code}`);
          }
        }
      } else if (code in MatterCodeTable) {
        const size = MatterCodeTable[code];

        if (size && size.fs) {
          const qb64 = await this.#readCharacters(size.fs - size.hs);
          return code + qb64;
        } else if (size) {
          throw new Error(`Variable length currently not supported code=${code}`);
        }
      }
    }

    throw new Error(`Unknown code in ${code}`);
  }
}

async function* iter<T>(iterator: AsyncIterable<T>): AsyncIterableIterator<T> {
  for await (const item of iterator) {
    yield item;
  }
}

export async function* decode(input: AsyncIterable<Uint8Array>): AsyncIterableIterator<string> {
  const decoder = new Parser(iter(input));

  while (true) {
    const frame = await decoder.readOne();

    if (frame === null) {
      return;
    }

    yield frame;
  }
}

export interface Message {
  payload: KeyEvent;
  attachments: string[];
}

export async function* parse(input: AsyncIterable<Uint8Array>): AsyncIterableIterator<Message> {
  let payload: KeyEvent | null = null;
  let attachments: string[] = [];

  function reset(): Message {
    const result = { payload, attachments };
    payload = null;
    attachments = [];
    return result as Message;
  }

  for await (const frame of decode(input)) {
    if (frame.startsWith("{")) {
      if (payload) {
        yield reset();
      }

      payload = JSON.parse(frame);
    } else {
      attachments.push(frame);
    }
  }

  if (payload) {
    yield reset();
  }
}

export interface Message {
  payload: KeyEvent;
  attachments: string[];
}
