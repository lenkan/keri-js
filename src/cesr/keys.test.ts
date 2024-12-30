import { expect, test } from "vitest";
import { SaltyKey } from "./keys.ts";

const salt = "0ACDEyMzQ1Njc4OWxtbm9aBc";

test("Salty key first index", () => {
  const keys1 = new SaltyKey({ salt, password: "alice00" });
  expect(keys1.publicKey).toEqual("DIyH3rzq2PIQCbvBkL5Mlk1oC3XtLw5sZvjeRIdlZETf");
});

test("Salty key next index", () => {
  const keys1 = new SaltyKey({ salt, password: "alice11" });
  expect(keys1.publicKeyDigest).toEqual("ENjMMFdspI2HGfN_9fGX717d9VeygNr7UNAfK2fDGfyf");
});
