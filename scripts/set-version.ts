import { glob, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";

const ROOT = resolve(import.meta.dirname, "..");

const version = process.argv[2];

if (!version) {
  console.error("Usage: node scripts/set-version.ts <version>");
  process.exit(1);
}

// Sibling dependencies stay on the `workspace:*` protocol; `pnpm pack` resolves it to the exact
// version of the sibling being packed, which keeps every published package locked to one version.
for await (const file of glob("packages/*/package.json", { cwd: ROOT })) {
  const path = resolve(ROOT, file);
  const manifest = JSON.parse(await readFile(path, "utf8"));

  manifest.version = version;

  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`${manifest.name}@${version}`);
}
