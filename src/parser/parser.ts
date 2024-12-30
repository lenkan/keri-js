import { parseVersion } from "./version.ts";
import { Base64 } from "../cesr/base64.ts";
import { CounterCode, CounterCodeTable, IndexerCodeTable, MatterCodeTable } from "./codes.ts";

type CountContext = {
  code: keyof typeof CounterCodeTable;
  count: number;
};

export class Parser {
  #buffer: Uint8Array = new Uint8Array(0);
  #decoder = new TextDecoder();
  #index: number = 0;
  #countContext: CountContext;

  #finished() {
    return this.#index >= this.#buffer.length;
  }

  #peekBytes(size: number) {
    if (typeof size !== "number") {
      throw new Error(`Size must be a number, got '${size}'`);
    }

    return this.#buffer.slice(this.#index, this.#index + size);
  }

  #readBytes(size: number) {
    if (typeof size !== "number") {
      throw new Error(`Size must be a number, got '${size}'`);
    }

    const chunk = this.#peekBytes(size);
    this.#index += size;
    return chunk;
  }

  #readCharacters(count: number): string {
    const chunk = this.#readBytes(count);
    return this.#decoder.decode(chunk);
  }

  #readOne(): string {
    let code = "";

    while (code.length < 4) {
      code = this.#decoder.decode(this.#peekBytes(code.length + 1));

      if (code === "{") {
        const version = parseVersion(this.#peekBytes(23));
        return this.#readCharacters(version.size);
      }

      if (code.startsWith("-") && code in CounterCodeTable) {
        const size = CounterCodeTable[code];
        if (size.fs === null) {
          throw new Error("Variable length currently not supported");
        }

        const qb64 = this.#readCharacters(size.fs);
        const count = Base64.toInt(qb64.slice(size.hs));

        if (code === CounterCode.AttachmentGroup || code === CounterCode.BigAttachmentGroup) {
          // Attachment group, currently no need to keep track of the count
        } else {
          // Stores the counter and expected count so we know what to expect next
          this.#countContext = {
            code,
            count,
          };
        }

        return qb64;
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
        let code = "";

        while (code.length < 2) {
          code = this.#decoder.decode(this.#peekBytes(code.length + 1));
          const size = IndexerCodeTable[code];

          if (size.fs === null) {
            throw new Error(`Variable length not supported`);
          }

          if (size) {
            this.#countContext.count--;
            return this.#readCharacters(size.fs);
          }
        }

        throw new Error(`Expected indexer code, got ${code}`);
      } else if (code in MatterCodeTable) {
        const size = MatterCodeTable[code];

        if (size.fs === null) {
          throw new Error(`Variable length not supported`);
        }

        return this.#readCharacters(size.fs);
      }
    }

    throw new Error(`Unknown code in ${code}`);
  }

  parse(data: Uint8Array): string[] {
    this.#buffer = data;

    const result: string[] = [];

    while (!this.#finished()) {
      result.push(this.#readOne());
    }

    return result;
  }
}

export function parse(data: Uint8Array): string[] {
  const parser = new Parser();
  return parser.parse(data);
}

export async function* parseStream(stream: ReadableStream<Uint8Array>): AsyncIterableIterator<Message> {
  const decoder = new Parser();

  let payload: unknown = null;
  let attachments: string[] = [];

  function reset(): Message {
    const result = { payload, attachments };
    payload = null;
    attachments = [];
    return result;
  }

  for await (const chunk of stream) {
    for (const frame of decoder.parse(chunk)) {
      if (frame.startsWith("{")) {
        if (payload) {
          yield reset();
        }

        payload = JSON.parse(frame);
      } else {
        attachments.push(frame);
      }
    }
  }

  if (payload) {
    yield reset();
  }
}

export interface Message {
  payload: unknown;
  attachments: string[];
}
