import { glob, readdir, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const PACKAGES = await readdir(resolve(ROOT, "packages"));

const importRegex = /(?:from|import)\s+["']([^"']+)["']/g;
const violations: string[] = [];

function owner(absFile: string): { pkg: string; src: string; module: string } | null {
  for (const pkg of PACKAGES) {
    const src = resolve(ROOT, "packages", pkg, "src");
    const within = relative(src, absFile);
    if (!within.startsWith("..")) {
      return { pkg, src, module: within.split("/")[0] };
    }
  }

  return null;
}

// Everything outside a package's `src` — apps, scripts, interop and consumer tests — consumes the
// libraries as a published package would, so it must enter through a bare specifier.
const files = glob(
  ["packages/*/src/**/*.ts", "apps/**/*.{ts,tsx}", "scripts/**/*.ts", "test_interop/**/*.ts", "test_consumer/**/*.ts"],
  { cwd: ROOT },
);

for await (const file of files) {
  const absFile = resolve(ROOT, file);
  const from = owner(absFile);
  const content = await readFile(absFile, "utf8");

  for (const match of content.matchAll(importRegex)) {
    const spec = match[1];
    if (!spec.startsWith(".")) {
      continue;
    }

    const absTarget = resolve(dirname(absFile), spec);
    const to = owner(absTarget);

    if (from === null) {
      if (to !== null) {
        violations.push(`${file}: imports "${spec}" — reach ${to.pkg} through its package name`);
      }
      continue;
    }

    if (to === null || to.pkg !== from.pkg) {
      violations.push(`${file}: imports "${spec}" — leaves package ${from.pkg}, use a package name`);
      continue;
    }

    if (to.module === from.module) {
      continue;
    }

    // Either the package entry (`src/main.ts`) or a submodule's (`src/<mod>/main.ts`).
    const target = relative(from.src, absTarget);
    if (target !== "main.ts" && target !== `${to.module}/main.ts`) {
      violations.push(`${file}: imports "${spec}" — must target src/main.ts or ../${to.module}/main.ts`);
    }
  }
}

if (violations.length > 0) {
  for (const v of violations) {
    console.error(v);
  }
  process.exit(1);
}
