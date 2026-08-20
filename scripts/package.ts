import { cp, mkdir, rm } from "node:fs/promises";

// The upload root: `server.js` carries its dependencies inlined, and `static`
// sits where the server looks for it by default, so the deployed app needs no
// manifest, no install step and no path configuration.
const out = "dist";

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

await cp("apps/verifier-server/dist/server.js", `${out}/server.js`);
await cp("apps/verifier/dist", `${out}/static`, { recursive: true });

console.log(`Packaged ${out}/server.js and ${out}/static`);
