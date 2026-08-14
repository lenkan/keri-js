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

const names = new Set(PACKAGES);

for (const name of PACKAGES) {
  const path = resolve(ROOT, "packages", name, "package.json");
  const manifest = JSON.parse(await readFile(path, "utf8"));

  manifest.version = version;

  // Sibling packages are pinned exactly, so the two versions can never drift apart in a release.
  for (const dependency of Object.keys(manifest.dependencies ?? {})) {
    if (names.has(dependency)) {
      manifest.dependencies[dependency] = version;
    }
  }

  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`${name}@${version}`);
}
