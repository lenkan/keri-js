#!/usr/bin/env node
import process from "node:process";
import { execute } from "./cli.ts";
import { resolveInputStream } from "./input.ts";

try {
  await execute({
    args: process.argv.slice(2),
    read: resolveInputStream,
  });
} catch (error) {
  if (error instanceof Error) {
    process.stderr.write("Error: ");
    process.stderr.write(error.message);
    process.stderr.write("\n");
  }
  process.exit(1);
}
