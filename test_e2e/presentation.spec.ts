import { expect, type Page, test } from "@playwright/test";
import type { KERIPy } from "../test_utils/keripy.ts";
import { issueCredential } from "./credential.ts";
import { login, waitForApi } from "./login.ts";

let said: string;
let stream: string;
let kli: KERIPy;

test.beforeAll(async () => {
  await waitForApi();

  ({ said, stream, kli } = await issueCredential());
});

/**
 * Logs in, opens the IPEX tab and presents the credential by running the commands the page prints.
 * Reading them back out is itself an assertion that the page printed usable ones.
 */
async function present(page: Page): Promise<void> {
  await login(page, kli);
  await page.getByRole("tab", { name: "Present over IPEX" }).click();

  const commands = await page.getByRole("tabpanel").locator("pre").innerText();

  const oobi = commands.match(/--oobi (\S+)/)?.[1];
  const recipient = commands.match(/--recipient (\S+)/)?.[1];
  const token = commands.match(/--message (\S+)/)?.[1];

  if (!oobi || !recipient || !token) {
    throw new Error(`Presentation commands were missing an oobi, recipient or token:\n${commands}`);
  }

  await kli.oobi.resolve(oobi, "verifier");
  await kli.ipex.grant({ said, recipient, message: token });
}

test("verifies a credential presented over IPEX", async ({ page }) => {
  await present(page);

  await expect(page.getByText("Credential presented. The result is below.")).toBeVisible();
  await expect(page.getByText("Verified", { exact: true })).toBeVisible();
  await expect(page.getByText(said)).toBeVisible();

  // Nothing may fail: the grant carries the issuer KEL and registry events alongside the credential,
  // so every check but the offline-only schema one has what it needs.
  await expect(page.getByText("✗")).toHaveCount(0);
});

test("clears the last result when a new session starts", async ({ page }) => {
  await present(page);

  await expect(page.getByText(said)).toBeVisible();

  // The verdict belongs to the presentation that produced it, so asking for a new session must not
  // leave the old result sitting underneath the new instructions.
  await page.getByRole("button", { name: "Present another" }).click();

  await expect(page.getByText(said)).toBeHidden();
  await expect(page.getByText("Verified", { exact: true })).toBeHidden();
  await expect(page.getByText("Waiting for a presentation…")).toBeVisible();
});

test("keeps each tab's result to itself", async ({ page }) => {
  await login(page, kli);

  // Verify on the stream tab first.
  await page.getByRole("button", { name: "Paste a stream instead" }).click();
  const textarea = page.getByRole("textbox");
  await textarea.fill(stream);
  await textarea.blur();
  await expect(page.getByText(said)).toBeVisible();

  // The IPEX tab has verified nothing, so it must not show the stream tab's verdict.
  await page.getByRole("tab", { name: "Present over IPEX" }).click();
  await expect(page.getByText(said)).toBeHidden();
  await expect(page.getByText("Waiting for a presentation…")).toBeVisible();

  // Going back shows it again: switching away hides a result, it does not discard it.
  await page.getByRole("tab", { name: "Bring a stream" }).click();
  await expect(page.getByText(said)).toBeVisible();
});
