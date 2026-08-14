import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";

const ROOT = resolve(import.meta.dirname, "..");
const PACKAGES = ["cesr", "keri"];

const version = process.argv[2];

if (!version) {
  console.error("Usage: node scripts/set-version.ts <version>");
  process.exit(1);
}

// Sibling dependencies stay on the `workspace:*` protocol here; `pnpm pack` resolves it to the
// exact version of the sibling being packed, which keeps the two locked together in a release.
for (const name of PACKAGES) {
  const path = resolve(ROOT, "packages", name, "package.json");
  const manifest = JSON.parse(await readFile(path, "utf8"));

  manifest.version = version;

  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`${name}@${version}`);
}
