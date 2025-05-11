import { glob, rm } from "node:fs/promises";

async function clean() {
  for (const pattern of [
    "dist",
    "node_modules",
    ".venv",
  ]) {
    for await (const entry of glob(pattern)) {
      try {
        console.log(`Removing ${entry}`);
        await rm(entry, { recursive: true });
      } catch {
        // ignore
      }
    }
  }
}

await clean();
