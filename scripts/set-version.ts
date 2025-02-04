import { execSync } from "node:child_process";
import { glob, readFile, writeFile } from "node:fs/promises";

const changes = execSync("git status --porcelain").toString().trim();
if (changes && !process.argv.includes("--skip-git-check") && !process.argv.includes("--dry-run")) {
  throw new Error(`Working directory is not clean\n\n ${changes}`);
}

const hash = execSync("git rev-parse --short HEAD").toString().trim();
for await (const pkg of glob("packages/*/package.json")) {
  const packageJSON = JSON.parse(await readFile(pkg, "utf8"));
  if (!packageJSON.private) {
    const version = `${packageJSON.version}-dev.${hash}`;
    packageJSON.version = version;

    if (!process.argv.includes("--dry-run")) {
      await writeFile(pkg, JSON.stringify(packageJSON, null, 2) + "\n");
    } else {
      console.log(`${packageJSON.name}: ${version}`);
    }
  }
}
