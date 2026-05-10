import { glob, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const SRC = resolve(ROOT, "src");

const importRegex = /(?:from|import)\s+["']([^"']+)["']/g;
const violations: string[] = [];

for await (const file of glob("src/**/*.ts", { cwd: ROOT })) {
  const absFile = resolve(ROOT, file);
  const moduleOfFile = relative(SRC, absFile).split("/")[0];
  const content = await readFile(absFile, "utf8");
  for (const match of content.matchAll(importRegex)) {
    const spec = match[1];
    if (!spec.startsWith(".")) {
      continue;
    }
    const targetAbs = resolve(dirname(absFile), spec);
    const relFromSrc = relative(SRC, targetAbs);
    if (relFromSrc.startsWith("..")) {
      continue;
    }
    const targetModule = relFromSrc.split("/")[0];
    if (targetModule === moduleOfFile) {
      continue;
    }
    if (relFromSrc !== `${targetModule}/main.ts`) {
      violations.push(`${file}: imports "${spec}" — cross-submodule imports must target ../${targetModule}/main.ts`);
    }
  }
}

if (violations.length > 0) {
  for (const v of violations) {
    console.error(v);
  }
  process.exit(1);
}
