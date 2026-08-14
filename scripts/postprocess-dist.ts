import { glob, readFile, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");

// `rewriteRelativeImportExtensions` rewrites .ts -> .js in emitted JavaScript but leaves the
// declarations pointing at .ts, so the specifiers name files that do not exist in dist. tsc resolves
// them anyway by mapping `./x.ts` to `./x.d.ts`; Deno does not. Reproduced on TypeScript 5.9, 6.0
// and 7.0. Tracked upstream as microsoft/TypeScript#61037, open and accepting a PR — drop this half
// once it ships.
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
// applies the exports map, and unlike tsc it does not pick up a .d.ts sitting next to a .js of the
// same name — it has to be told. `@ts-self-types` is Deno's documented way to say it, and is inert
// everywhere else. Consumers installing the published tarballs get declarations through the `types`
// condition instead. https://docs.deno.com/runtime/fundamentals/typescript/
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
