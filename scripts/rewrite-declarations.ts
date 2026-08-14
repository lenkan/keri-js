import { glob, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

// `rewriteRelativeImportExtensions` rewrites .ts -> .js in emitted JavaScript but leaves the
// declarations pointing at .ts. TypeScript resolves those itself; Deno and other checkers do not.
const ROOT = resolve(import.meta.dirname, "..");
const specifier = /(from\s*|import\s*\(\s*)(["'])(\.[^"']*)\.ts\2/g;

for await (const file of glob("packages/*/dist/**/*.d.ts", { cwd: ROOT })) {
  const path = resolve(ROOT, file);
  const content = await readFile(path, "utf8");
  const rewritten = content.replaceAll(specifier, "$1$2$3.js$2");

  if (rewritten !== content) {
    await writeFile(path, rewritten);
  }
}
