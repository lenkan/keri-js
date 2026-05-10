import { glob, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const SRC = resolve(ROOT, "src");

const pkg = JSON.parse(await readFile(resolve(ROOT, "package.json"), "utf8"));
const publicEntries = new Set<string>();
for (const value of Object.values(pkg.exports as Record<string, string>)) {
  publicEntries.add(resolve(ROOT, value.replace(/^\.\/dist\//, "src/").replace(/\.js$/, ".ts")));
}

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
    const isMain = relFromSrc === `${targetModule}/main.ts`;
    const isPublic = publicEntries.has(targetAbs);
    if (!isMain && !isPublic) {
      violations.push(
        `${file}: imports "${spec}" — cross-submodule imports must target ../${targetModule}/main.ts (or a package export)`,
      );
    }
  }
}

if (violations.length > 0) {
  for (const v of violations) {
    console.error(v);
  }
  process.exit(1);
}
