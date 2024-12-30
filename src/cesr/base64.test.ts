import { test, expect } from "vitest";
import { Base64 } from "./base64.ts";

test("Create base 64 number", () => {
  expect(Base64.fromInt(0)).toEqual("A");
  expect(Base64.fromInt(1)).toEqual("B");
  expect(Base64.fromInt(1, 2)).toEqual("AB");
});

test("Parse base 64 number", () => {
  expect(Base64.toInt("A")).toEqual(0);
  expect(Base64.toInt("AB")).toEqual(1);
  expect(Base64.toInt("B")).toEqual(1);
  expect(Base64.toInt("BA")).toEqual(64);
  expect(Base64.toInt("An")).toEqual(39);
});
