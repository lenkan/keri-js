import { glob, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const SRC = resolve(ROOT, "src");

const importRegex = /(?:from|import)\s+["']([^"']+)["']/g;
const violations: string[] = [];

// Apps consume the library from outside `src`, so they have no owning submodule
// and must enter through an entry point like anyone else.
for await (const file of glob(["src/**/*.ts", "apps/**/*.{ts,tsx}"], { cwd: ROOT })) {
  const absFile = resolve(ROOT, file);
  const owner = relative(SRC, absFile).startsWith("..") ? null : relative(SRC, absFile).split("/")[0];
  const content = await readFile(absFile, "utf8");

  for (const match of content.matchAll(importRegex)) {
    const spec = match[1];
    if (!spec.startsWith(".")) {
      continue;
    }

    const target = relative(SRC, resolve(dirname(absFile), spec));
    if (target.startsWith("..")) {
      continue;
    }

    const targetModule = target.split("/")[0];
    if (owner !== null && targetModule === owner) {
      continue;
    }

    // Either the package entry (`src/main.ts`) or a submodule's (`src/<mod>/main.ts`).
    if (target !== "main.ts" && target !== `${targetModule}/main.ts`) {
      violations.push(`${file}: imports "${spec}" — must target src/main.ts or ../${targetModule}/main.ts`);
    }
  }
}

if (violations.length > 0) {
  for (const v of violations) {
    console.error(v);
  }
  process.exit(1);
}
