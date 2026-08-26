import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";

const version = process.argv[2];

if (!version) {
  console.error("Usage: node scripts/set-version.ts <version>");
  process.exit(1);
}

const path = resolve(import.meta.dirname, "..", "package.json");
const manifest = JSON.parse(await readFile(path, "utf8"));

manifest.version = version;

await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`${manifest.name}@${version}`);
