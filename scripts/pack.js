// @ts-check
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, glob, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

const outdir = ".pack";

if (existsSync(outdir)) {
  await rm(outdir, { recursive: true });
}

await mkdir(outdir);
const packageJSON = JSON.parse(await readFile("package.json", "utf8"));

for await (const file of glob([
  "src",
  "fixtures",
  "scripts",
  "tsconfig*.json",
  "package-lock.json",
  "eslint.config.js",
  "README.md",
])) {
  await cp(file, join(outdir, file), { recursive: true });
}

const changes = execSync("git status --porcelain").toString().trim();
if (changes) {
  throw new Error(`Working directory is not clean\n\n ${changes}`);
}

const hash = execSync("git rev-parse --short HEAD").toString().trim();
packageJSON.version = `${packageJSON.version}-dev.${hash}`;
await writeFile(join(outdir, "package.json"), JSON.stringify(packageJSON, null, 2) + "\n");

execSync("npm ci", { cwd: outdir, stdio: "inherit" });
execSync("npm test", { cwd: outdir, stdio: "inherit" });
execSync("npm run build", { cwd: outdir, stdio: "inherit" });
execSync("npm pack", { cwd: outdir, stdio: "inherit" });
