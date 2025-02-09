// @ts-check
import { readFile, glob, writeFile } from "node:fs/promises";

async function configure() {
  for (const pattern of ["packages/*/package.json", "packages/@kerijs/*/package.json"]) {
    for await (const entry of glob(pattern)) {
      const packageJSON = JSON.parse(await readFile(entry, "utf8"));
      packageJSON.scripts = packageJSON.scripts || {};
      packageJSON.scripts.test = [
        "node",
        "--test",
        "--test-reporter=spec",
        "--no-warnings",
        "--experimental-strip-types",
      ].join(" ");

      packageJSON.scripts.lint = "eslint";

      await writeFile(entry, JSON.stringify(packageJSON, null, 2) + "\n");
      console.log(`Configured ${entry}`);
    }
  }
}

await configure();
