// @ts-check
import { glob, rm } from "node:fs/promises";

async function clean() {
  for (const pattern of ["dist", "node_modules", "packages/*/dist", "packages/*/node_modules"]) {
    for await (const entry of glob(pattern)) {
      try {
        await rm(entry, { recursive: true });
      } catch {
        // ignore
      }
    }
  }
}

await clean();
