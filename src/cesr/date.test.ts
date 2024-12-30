import { expect, test } from "vitest";
import cesr from "../parser/cesr-encoding.ts";

test("cesr date", () => {
  const result = cesr.encodeDate(new Date(Date.parse("2024-11-23T16:02:27.123Z")));
  expect(result).toEqual("1AAG2024-11-23T16c02c27d123000p00c00");
});
