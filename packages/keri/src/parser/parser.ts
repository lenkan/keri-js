import { parseVersion } from "./version.ts";
import { decodeBase64Int } from "./base64.ts";
import { type CodeSize, CounterCode, CounterCodeTable, IndexerCodeTable, MatterCodeTable } from "./codes.ts";
import type { KeyEvent } from "../events/main.ts";

export interface Frame {
  code: string;
  text: string;
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

  async #readIndexer(): Promise<Frame> {
    let size: CodeSize | null = null;

    let code = "";
    while (code.length < 4) {
      const next = await this.#readBytes(1);
      if (next === null) {
        throw new Error("Unexpected end of stream");
      }

      code += this.#decoder.decode(next);
      size = IndexerCodeTable[code];

      if (size && size.fs !== null) {
        const qb64 = await this.#readCharacters(size.fs - size.hs);
        return { code, text: qb64 };
      }
    }

    throw new Error(`Unexpected end of stream '${code}'`);
  }

  async #readPrimitive(): Promise<Frame> {
    let size: CodeSize | null = null;

    let code = "";
    while (code.length < 4) {
      const next = await this.#readBytes(1);
      if (next === null) {
        throw new Error("Unexpected end of stream");
      }

      code += this.#decoder.decode(next);
      size = MatterCodeTable[code];

      if (size && size.fs !== null) {
        const qb64 = await this.#readCharacters(size.fs - size.hs);
        return { code, text: qb64 };
      }
    }

    throw new Error(`Unexpected end of stream '${code}'`);
  }

  private async *readCounter(): AsyncIterableIterator<Frame> {
    let code = "-";

    let size: CodeSize | null = null;
    while (!size && code.length < 4) {
      const next = await this.#readBytes(1);
      if (next === null) {
        throw new Error("Unexpected end of stream");
      }

      code += this.#decoder.decode(next);
      size = CounterCodeTable[code];
      if (size && size.fs !== null) {
        const qb64 = await this.#readCharacters(size.fs - size.hs);
        yield { code, text: qb64 };

        switch (code) {
          case CounterCode.ControllerIdxSigs:
          case CounterCode.WitnessIdxSigs: {
            let count = decodeBase64Int(qb64);

            while (count > 0) {
              yield this.#readIndexer();
              count--;
            }

            break;
          }
          case CounterCode.NonTransReceiptCouples:
          case CounterCode.SealSourceCouples:
          case CounterCode.FirstSeenReplayCouples: {
            let count = decodeBase64Int(qb64);

            while (count > 0) {
              yield this.#readPrimitive();
              yield this.#readPrimitive();
              count--;
            }
            break;
          }
        }
      }
    }
  }

  async *read(): AsyncIterableIterator<Frame> {
    while (true) {
      const start = await this.#readBytes(1);
      if (start === null) {
        return;
      }

      const code = this.#decoder.decode(start);
      if (code === "{") {
        const prefix = this.#decoder.decode(start) + (await this.#readCharacters(22));
        const version = parseVersion(prefix);
        const text = prefix + (await this.#readCharacters(version.size - prefix.length));
        yield { code, text };
      } else if (code === "-") {
        for await (const frame of this.readCounter()) {
          yield frame;
        }
      } else {
        throw new Error(`Unexpected start of stream '${code}'`);
      }
    }
  }
}

async function* iter<T>(iterator: AsyncIterable<T>): AsyncIterableIterator<T> {
  for await (const item of iterator) {
    yield item;
  }
}

export async function* decode(input: AsyncIterable<Uint8Array>): AsyncIterableIterator<string> {
  const decoder = new Parser(iter(input));

  for await (const frame of decoder.read()) {
    if (frame.code === "{") {
      yield frame.text;
    } else {
      yield frame.code + frame.text;
    }
  }
}

export async function* parse(input: AsyncIterable<Uint8Array>): AsyncIterableIterator<Message> {
  const decoder = new Parser(iter(input));

  let payload: KeyEvent | null = null;
  let group: string | null = null;
  let attachments: Record<string, string[]> = {};

  for await (const frame of decoder.read()) {
    if (frame === null) {
      return;
    }

    if (frame.code === "{") {
      if (payload) {
        yield { payload, attachments };
      }

      payload = JSON.parse(frame.text);
      attachments = {};
      group = null;
    } else if (frame.code.startsWith("-")) {
      group = frame.code;
    } else if (group) {
      attachments[group] = [...(attachments[group] ?? []), frame.code + frame.text];
    }
  }

  if (payload) {
    yield { payload, attachments };
  }
}

export interface Message {
  payload: KeyEvent;
  attachments: Record<string, string[]>;
}
