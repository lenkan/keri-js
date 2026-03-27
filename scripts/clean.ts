import { glob, rm } from "node:fs/promises";

for (const pattern of ["**/dist", "**/node_modules", "**/.venv"]) {
  for await (const entry of glob(pattern)) {
    console.log(`Removing ${entry}`);
    await rm(entry, { recursive: true, force: true });
  }
}
