import { glob } from "node:fs/promises";
import { execSync } from "node:child_process";
import { setTimeout } from "node:timers/promises";

await (async function () {
  while (true) {
    try {
      const response = await fetch("http://localhost:5642/oobi");
      if (response.ok) {
        return;
      }
    } catch {
      //
    }

    console.log("Waiting for KERI witness demo to start...");
    await setTimeout(1000);
  }
})();

for await (const file of glob("test_scripts/test_*.sh")) {
  console.log(`Running test script: ${file}`);
  execSync(file, { stdio: "inherit" });
}
