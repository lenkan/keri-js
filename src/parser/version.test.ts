import { expect, test } from "vitest";
import { parseVersion } from "./version.ts";

// const DUMMY_VERSION = "PPPPVVVKKKKBBBB.";
// const DUMMY_LEGACY_VERSION = "PPPPvvKKKKllllll_";
const encoder = new TextEncoder();

test("Should parse legacy keri version", () => {
  const result = parseVersion(encoder.encode(JSON.stringify({ v: "KERI10JSON00000a_" })));
  expect(result).toMatchObject({
    protocol: "KERI",
    version: "10",
    format: "JSON",
    size: 10,
  });
});

test("Should parse keri version", () => {
  const result = parseVersion(encoder.encode(JSON.stringify({ v: "KERI201JSONAAAB." })));
  expect(result).toMatchObject({
    protocol: "KERI",
    version: "201",
    format: "JSON",
    size: 1,
  });
});
