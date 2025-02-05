import esbuild from "esbuild";
import { cp, glob, mkdir, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";

const outdir = "dist";

const isServing = process.argv.includes("--serve");
const context = await esbuild.context({
  outdir,
  entryPoints: ["src/main.tsx"],
  bundle: true,
  sourcemap: true,
});

await mkdir(outdir, { recursive: true });

await writeFile(
  join(outdir, "index.html"),
  [
    "<!DOCTYPE html>",
    "<html>",
    "  <head>",
    "    <title>Example App</title>",
    "    <meta charset='utf-8'>",
    "    <meta name='viewport' content='width=device-width, initial-scale=1'>",
    "    <link rel='stylesheet' href='main.css'>",
    "  </head>",
    "<body>",
    "<div id='root'></div>",
    "<script src='main.js'></script>",
    isServing ? "<script>new EventSource('/esbuild').addEventListener('change', () => location.reload())</script>" : "",
    "</body>",
    "</html>",
  ]
    .map((line) => line.trim())
    .join(""),
);

for await (const file of glob("public/*")) {
  await cp(file, join("dist", relative("public", file)), { recursive: true });
}

if (process.argv.includes("--serve")) {
  await context.watch({});
  const result = await context.serve({ servedir: "dist", port: 3000 });
  console.log(`Serving on http://localhost:${result.port}`);
} else {
  await context.rebuild();
  await context.dispose();
}

process.on("SIGINT", () => context.dispose());
process.on("SIGTERM", () => context.dispose());
