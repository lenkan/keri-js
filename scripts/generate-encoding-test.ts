import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

function toarray(buffer: Buffer): Uint8Array {
  const view = new Uint8Array(buffer.byteLength);

  for (let i = 0; i < buffer.length; ++i) {
    view[i] = buffer[i];
  }

  return view;
}

interface TestData {
  code: string;
  raw: Uint8Array;
  qb2: Uint8Array;
  qb64: string;
  qb64b: Uint8Array;
}

function parseIni(text: string): TestData {
  const encoder = new TextEncoder();
  return text
    .split("\n")
    .slice(1)
    .filter((line) => !!line.trim())
    .reduce<TestData>((acc, line) => {
      const [key, value] = line.split("=").map((part) => part.trim());

      if (acc[key]) {
        return acc;
      }

      switch (key) {
        case "qb64":
          return {
            ...acc,
            [key]: value,
            qb64b: encoder.encode(value.trim()),
          };
        case "code":
          return {
            ...acc,
            [key]: value,
          };
        case "raw":
        case "qb2":
          return {
            ...acc,
            [key]: toarray(Buffer.from(value.replaceAll("-", ""), "hex")),
          };
        default:
          return acc;
      }
    }, {} as TestData);
}

async function readVectors(code: string) {
  const dirname = "../cesr-test-vectors/test_vectors/primitives";
  const filenames = await readdir(dirname);

  const tests = await Promise.all(
    filenames
      .filter((name) => name.startsWith(code))
      .map(async (filename) => {
        const text = await readFile(join(dirname, filename), "utf-8");
        return parseIni(text);
      }),
  );

  return tests;
}

const vectors = Object.values(Object.groupBy(await readVectors(""), (v) => v.code)).flatMap(
  (v) => v?.slice(0, 2) ?? [],
);

console.log(
  [
    'import { test } from "node:test";',
    'import assert from "node:assert";',
    'import cesr from "./cesr-encoding.ts"',
    "",
    ...vectors
      .filter((vector) => vector.raw.byteLength < 500)
      .flatMap((vector) => {
        return [
          `test(\`Decode ${vector.qb64}\`, () => {`,
          `  const { code, buffer: raw } = cesr.decode("${vector.qb64}");`,
          "",
          `  assert.strictEqual(code, "${vector.code}");`,
          `  assert.deepStrictEqual(raw, new Uint8Array([${vector.raw.map((i) => i).join(", ")}]));`,
          "});",
          "",
          `test(\`Encode ${vector.qb64}\`, () => {`,
          `  const raw = new Uint8Array([${vector.raw.map((i) => i).join(", ")}]);`,
          `  assert.strictEqual(cesr.encode("${vector.code}", raw), "${vector.qb64}");`,
          "});",
        ];
      }),
    "",
  ].join("\n"),
);
