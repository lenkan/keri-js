import { glob, readFile, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");

// `rewriteRelativeImportExtensions` rewrites .ts -> .js in emitted JavaScript but leaves the
// declarations pointing at .ts — identical on TypeScript 5.9, 6.0 and 7.0, so it is the intended
// behaviour, not a bug to wait out. Inside a .d.ts the specifier is never executed and TypeScript's
// own resolver maps `./x.ts` to `./x.d.ts`; Deno has no such mapping and fails to resolve it.
const tsSpecifier = /(from\s*|import\s*\(\s*)(["'])(\.[^"']*)\.ts\2/g;

for await (const file of glob("packages/*/dist/**/*.d.ts", { cwd: ROOT })) {
  const path = resolve(ROOT, file);
  const content = await readFile(path, "utf8");
  const rewritten = content.replaceAll(tsSpecifier, "$1$2$3.js$2");

  if (rewritten !== content) {
    await writeFile(path, rewritten);
  }
}

// Deno resolves a workspace-linked package through its symlink to a plain file:// path, so it never
// applies the exports map and type-checks the emitted JavaScript instead of the declarations. The
// pragma points each emitted file at its own .d.ts. Consumers installing the published tarballs get
// the declarations through the `types` condition and ignore this.
const selfTypes = '// @ts-self-types="./NAME.d.ts"\n';

for await (const file of glob("packages/*/dist/**/*.js", { cwd: ROOT })) {
  const path = resolve(ROOT, file);
  const content = await readFile(path, "utf8");

  if (content.startsWith("// @ts-self-types=")) {
    continue;
  }

  const name = basename(file, ".js");
  await writeFile(path, selfTypes.replace("NAME", name) + content);
}
