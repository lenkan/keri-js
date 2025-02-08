import type { WriterFunction } from "ts-morph";
import { Project, ScriptTarget, VariableDeclarationKind } from "ts-morph";
import { execSync } from "child_process";
import { writeFile } from "fs/promises";

interface CodeEntry {
  type: "matter" | "indexer" | "counter";
  code: string;
  name: string;
  hs: number;
  ss: number;
  xs: number | null;
  fs: number | null;
  ls: number | null;
}

execSync("python3 -m venv .venv", { stdio: "inherit" });
execSync(".venv/bin/pip install keri==1.2.3", { stdio: "inherit" });
const codes: CodeEntry[] = JSON.parse(execSync(".venv/bin/python ./scripts/generate-codec.py", {}).toString("utf8"));

const matter = codes.filter((c) => c.type === "matter");
const indexer = codes.filter((c) => c.type === "indexer");
const counters = codes.filter((c) => c.type === "counter");

const project = new Project({
  compilerOptions: {
    target: ScriptTarget.ES2015,
    outDir: "dist",
    declaration: true,
  },
});

const file = project.createSourceFile("codes.ts", {}, {});

file.addInterface({
  name: "CodeSize",
  isExported: true,
  properties: [
    { name: "hs", type: "number" },
    { name: "ss", type: "number" },
    { name: "xs", type: "number | null" },
    { name: "fs", type: "number | null" },
    { name: "ls", type: "number | null" },
  ],
});

function writeEntries(entries: CodeEntry[]): WriterFunction {
  return (writer) => {
    writer.block(() => {
      entries.forEach((entry) => {
        writer.writeLine(
          `["${entry.code}"]: { hs: ${entry.hs}, ss: ${entry.ss}, xs: ${entry.xs}, fs: ${entry.fs ?? "null"}, ls: ${entry.ls ?? "null"} },`,
        );
      });
    });

    return writer;
  };
}

function writeCodes(entries: CodeEntry[]): WriterFunction {
  return (writer) => {
    writer.block(() => {
      entries.forEach((entry) => {
        writer.writeLine(`["${entry.name}"]: "${entry.code}",`);
      });
    });

    return writer;
  };
}

file.addVariableStatements([
  {
    isExported: true,
    declarationKind: VariableDeclarationKind.Const,
    declarations: [
      {
        name: "MatterCodeTable",
        type: "Record<string, CodeSize>",
        initializer: writeEntries(matter),
      },
    ],
  },
  {
    isExported: true,
    declarationKind: VariableDeclarationKind.Const,
    declarations: [
      {
        name: "MatterCode",
        initializer: writeCodes(matter),
      },
    ],
  },
]);

file.addVariableStatement({
  isExported: true,
  declarationKind: VariableDeclarationKind.Const,
  declarations: [
    {
      name: "IndexerCodeTable",
      type: "Record<string, CodeSize>",
      initializer: writeEntries(indexer),
    },
  ],
});

file.addVariableStatement({
  isExported: true,
  declarationKind: VariableDeclarationKind.Const,
  declarations: [
    {
      name: "IndexerCode",
      initializer: writeCodes(indexer),
    },
  ],
});

file.addVariableStatement({
  isExported: true,
  declarationKind: VariableDeclarationKind.Const,
  declarations: [
    {
      name: "CounterCodeTable",
      type: "Record<string, CodeSize>",
      initializer: writeEntries(counters),
    },
  ],
});

file.addVariableStatement({
  isExported: true,
  declarationKind: VariableDeclarationKind.Const,
  declarations: [
    {
      name: "CounterCode",
      initializer: writeCodes(counters),
    },
  ],
});

await writeFile("codec.json", JSON.stringify(codes, null, 2));
await writeFile("packages/keri/src/parser/codes.ts", file.print());
execSync("pnpm prettier --write packages/keri/src/parser/codes.ts", { stdio: "inherit" });
execSync("pnpm prettier --write codec.json", { stdio: "inherit" });
