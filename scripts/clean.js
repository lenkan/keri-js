// @ts-check
import { rm } from "node:fs/promises";

/**
 * @param {import("fs").PathLike} dir
 */
async function clean(dir) {
  try {
    await rm(dir, { recursive: true });
  } catch {
    // ignore
  }
}

await Promise.all(["dist", "node_modules"].map(clean));
