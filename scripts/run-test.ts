// @ts-check
import { spec } from "node:test/reporters";
import { run } from "node:test";
import process from "node:process";

const args = process.argv.filter((arg) => !arg.startsWith("--"));
const pattern = args.length > 2 ? args[2] : "src/**/*.test.ts";

run({
  globPatterns: [pattern],
  watch: process.argv.includes("--watch"),
  only: process.argv.includes("--only"),
})
  .compose(spec())
  .pipe(process.stdout);
