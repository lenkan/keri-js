import { expect, test } from "@playwright/test";
import { KERIPy } from "../test_utils/keripy.ts";
import { login, waitForApi } from "./login.ts";

let kli: KERIPy;

test.beforeAll(async () => {
  await waitForApi();

  kli = new KERIPy();
  await kli.init();
  await kli.incept({ toad: 0 });
});

test("logs in with the commands the wizard prints", async ({ page }) => {
  await login(page, kli);

  // `.first()`: an icp-only AID's establishment digest IS the AID, so the same
  // string renders in two fields.
  await expect(page.getByText(await kli.aid()).first()).toBeVisible();
  await expect(page.getByText("None — witness-less identifier")).toBeVisible();
});

test("stays logged in across a reload", async ({ page }) => {
  await login(page, kli);

  await page.reload();

  await expect(page.getByText("Logged in", { exact: true })).toBeVisible();
  await expect(page.getByText(await kli.aid()).first()).toBeVisible();
});

test("logging out returns to the gate with a fresh session", async ({ page }) => {
  await login(page, kli);

  await page.getByRole("button", { name: "Log out" }).click();

  await expect(page.getByText("Waiting for your key event log…")).toBeVisible();
  await expect(page.getByText("Logged in", { exact: true })).toBeHidden();
});
