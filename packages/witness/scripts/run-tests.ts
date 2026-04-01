import { execSync } from "node:child_process";
import { glob } from "node:fs/promises";

for await (const file of glob("test_scripts/*.sh")) {
  console.log(`Running ${file}`);
  execSync(file, { stdio: "inherit" });
}
