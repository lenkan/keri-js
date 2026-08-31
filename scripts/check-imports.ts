import { glob, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const SRC = resolve(ROOT, "src");

const manifest = JSON.parse(await readFile(resolve(ROOT, "package.json"), "utf8"));
const NAME: string = manifest.name;
const dependencies = new Set(Object.keys({ ...manifest.dependencies, ...manifest.peerDependencies }));

const importRegex = /(?:from|import)\s+["']([^"']+)["']/g;
const violations: string[] = [];

/** Path relative to `src`, or null when the file lives outside the published source. */
function locate(absFile: string): string | null {
  const path = relative(SRC, absFile);
  return path.startsWith("..") ? null : path;
}

function submodule(path: string): string {
  return path.split("/")[0];
}

// `main.ts` is what a submodule shows consumers; `internal.ts` is what it shows its siblings. The
// split keeps the four namespaces the size of their public list, and makes an import of the second
// say at its own call site that it is reaching past that.
function isEntryPoint(path: string): boolean {
  return path === "main.ts" || path === `${submodule(path)}/main.ts` || path === `${submodule(path)}/internal.ts`;
}

// `test_consumer` is the one place that must reach the library the way a dependent does, through the
// package name, so it resolves the `exports` map and `dist`. Everything else outside `src` may
// import the source directly — but still only through a `main.ts`, never a submodule's internals.
const PACKAGE_NAME_REQUIRED = "test_consumer/";

const files = glob(
  [
    "src/**/*.ts",
    "test_vectors/**/*.ts",
    "scripts/**/*.ts",
    "test_consumer/**/*.ts",
    "test_interop/**/*.ts",
    "test_utils/**/*.ts",
  ],
  { cwd: ROOT },
);

for await (const file of files) {
  const absFile = resolve(ROOT, file);
  const from = locate(absFile);
  const content = await readFile(absFile, "utf8");

  for (const match of content.matchAll(importRegex)) {
    const spec = match[1];

    if (!spec.startsWith(".")) {
      if (from === null) {
        continue;
      }

      if (spec.startsWith("node:")) {
        // Keeps src runnable on Deno and in the browser. Tests are exempt — they run on Node.
        if (!file.endsWith(".test.ts")) {
          violations.push(`${file}: imports "${spec}" — node: builtins do not belong in src`);
        }
        continue;
      }

      // npm hoists, so an undeclared dependency would resolve here and break for everyone who
      // installs the published package. This check is what catches it.
      const name = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
      if (name !== NAME && !dependencies.has(name)) {
        violations.push(`${file}: imports "${spec}" — not a dependency of ${NAME}`);
      }
      continue;
    }

    const to = locate(resolve(dirname(absFile), spec));

    if (from === null) {
      if (to === null) {
        continue;
      }

      if (file.startsWith(PACKAGE_NAME_REQUIRED)) {
        violations.push(`${file}: imports "${spec}" — reach the library through "${NAME}"`);
      } else if (!isEntryPoint(to)) {
        violations.push(`${file}: imports "${spec}" — must target src/main.ts or src/${submodule(to)}/main.ts`);
      }
      continue;
    }

    if (to === null) {
      // Tests may reach `test_utils`. They are excluded from the published tarball, so the
      // boundary that protects consumers does not apply to them.
      if (file.endsWith(".test.ts") && resolve(dirname(absFile), spec).startsWith(resolve(ROOT, "test_utils"))) {
        continue;
      }

      violations.push(`${file}: imports "${spec}" — leaves src`);
      continue;
    }

    if (submodule(to) === submodule(from)) {
      continue;
    }

    if (!isEntryPoint(to)) {
      violations.push(
        `${file}: imports "${spec}" — must target src/main.ts, ../${submodule(to)}/main.ts or ../${submodule(to)}/internal.ts`,
      );
      continue;
    }

    // The package surface is assembled from what each submodule publishes, never from what it
    // keeps for its siblings.
    if (from === "main.ts" && to.endsWith("/internal.ts")) {
      violations.push(`${file}: imports "${spec}" — the public surface is built from main.ts only`);
    }
  }
}

if (violations.length > 0) {
  for (const v of violations) {
    console.error(v);
  }
  process.exit(1);
}
