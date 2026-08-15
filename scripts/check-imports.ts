import { glob, readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");

interface Package {
  name: string;
  src: string;
  dependencies: Set<string>;
}

const packages: Package[] = [];

for await (const file of glob("packages/*/package.json", { cwd: ROOT })) {
  const dir = resolve(ROOT, dirname(file));
  const manifest = JSON.parse(await readFile(resolve(ROOT, file), "utf8"));

  packages.push({
    name: manifest.name,
    src: resolve(dir, "src"),
    dependencies: new Set(Object.keys({ ...manifest.dependencies, ...manifest.peerDependencies })),
  });
}

const importRegex = /(?:from|import)\s+["']([^"']+)["']/g;
const violations: string[] = [];

interface Location {
  pkg: Package;
  path: string;
}

function locate(absFile: string): Location | null {
  for (const pkg of packages) {
    const path = relative(pkg.src, absFile);
    if (!path.startsWith("..")) {
      return { pkg, path };
    }
  }

  return null;
}

function submodule(location: Location): string {
  return location.path.split("/")[0];
}

// Everything outside a package's `src` — apps, scripts, interop and consumer tests — consumes the
// libraries as a published package would, so it must enter through a bare specifier.
const files = glob(
  [
    "packages/*/src/**/*.ts",
    "packages/*/test_vectors/**/*.ts",
    "apps/**/*.{ts,tsx}",
    "scripts/**/*.ts",
    "test_interop/**/*.ts",
    "test_consumer/**/*.ts",
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
        // Platform-specific bindings are confined to a submodule named `node`, so every other
        // submodule stays runnable on Deno and in the browser. Tests are exempt — they run on Node.
        if (submodule(from) !== "node" && !file.endsWith(".test.ts")) {
          violations.push(`${file}: imports "${spec}" — node: builtins belong in a "node" submodule`);
        }
        continue;
      }

      // A package may only import what it declares, or pnpm's isolated node_modules resolves it
      // through the workspace root and the published package breaks for everyone else.
      const name = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
      if (name !== from.pkg.name && !from.pkg.dependencies.has(name)) {
        violations.push(`${file}: imports "${spec}" — not a dependency of ${from.pkg.name}`);
      }
      continue;
    }

    const absTarget = resolve(dirname(absFile), spec);
    const to = locate(absTarget);

    if (from === null) {
      if (to !== null) {
        violations.push(`${file}: imports "${spec}" — reach ${to.pkg.name} through its package name`);
      }
      continue;
    }

    if (to === null || to.pkg !== from.pkg) {
      violations.push(`${file}: imports "${spec}" — leaves package ${from.pkg.name}, use a package name`);
      continue;
    }

    if (submodule(to) === submodule(from)) {
      continue;
    }

    // Either the package entry (`src/main.ts`) or a submodule's (`src/<mod>/main.ts`).
    if (to.path !== "main.ts" && to.path !== `${submodule(to)}/main.ts`) {
      violations.push(`${file}: imports "${spec}" — must target src/main.ts or ../${submodule(to)}/main.ts`);
    }
  }
}

if (violations.length > 0) {
  for (const v of violations) {
    console.error(v);
  }
  process.exit(1);
}
