import { createReadStream } from "fs";
import { expect, test } from "vitest";
import { parseStream } from "./parser.ts";

async function collect<T>(iterator: AsyncIterableIterator<T>): Promise<T[]> {
  const result: T[] = [];

  for await (const item of iterator) {
    result.push(item);
  }

  return result;
}

test("Test alice", { timeout: 100 }, async () => {
  const stream = ReadableStream.from(createReadStream("./fixtures/alice.json", {}));

  const result = await collect(parseStream(stream));

  expect(result).toHaveLength(2);
  expect(result[0].payload).toMatchObject({ t: "icp" });
  expect(result[1].payload).toMatchObject({ t: "ixn" });
});

test("Test witness", { timeout: 100 }, async () => {
  const stream = ReadableStream.from(createReadStream("./fixtures/witness.json", {}));

  const result = await collect(parseStream(stream));

  expect(result).toHaveLength(3);
  expect(result[0].payload).toMatchObject({ t: "icp" });
  expect(result[1].payload).toMatchObject({ t: "rpy" });
});
