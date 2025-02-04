// @ts-check
import { glob, rm } from "node:fs/promises";

async function clean(dir: string) {
  try {
    await rm(dir, { recursive: true });
  } catch {
    // ignore
  }
}

for(const pattern of ["dist", "node_modules", "packages/*/dist", "packages/*/node_modules"]) {
  for await (const entry of glob(pattern)) {
    await clean(entry);
  }
}

await Promise.all(["dist", "node_modules"].map(clean));
