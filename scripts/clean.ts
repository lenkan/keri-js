import { glob, rm } from "node:fs/promises";

// Build outputs only. Deliberately not driven off .gitignore, which also lists local state like
// .env and .vscode that clean must never touch. `**/*.tsbuildinfo` catches caches left outside
// dist/ by older checkouts, before tsBuildInfoFile moved into the output directory.
const patterns = ["**/dist", "**/node_modules", "**/*.tsbuildinfo", ".venv"];

for (const pattern of patterns) {
  for await (const entry of glob(pattern)) {
    console.log(`Removing ${entry}`);
    await rm(entry, { recursive: true, force: true });
  }
}
