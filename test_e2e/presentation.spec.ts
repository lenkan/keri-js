import { expect, test } from "@playwright/test";
import { BASE_URL } from "../playwright.config.ts";
import type { KERIPy } from "../test_utils/keripy.ts";
import { issueCredential } from "./credential.ts";

let said: string;
let kli: KERIPy;

test.beforeAll(async () => {
  // Unlike the file-drop tests, this one needs the relay behind the page, so fail with the command
  // that starts it rather than letting the first assertion time out.
  const response = await fetch(`${BASE_URL}/api/sessions`, { method: "POST" }).catch(() => null);

  if (!response?.ok) {
    throw new Error(
      `${BASE_URL}/api/sessions did not answer. Start the verifier server too ("pnpm run dev:verifier").`,
    );
  }

  ({ said, kli } = await issueCredential());
});

test("verifies a credential presented over IPEX", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("tab", { name: "Present over IPEX" }).click();

  // The page prints the commands a holder is meant to run, so reading the recipient and token back
  // out of them is also an assertion that it printed the right ones.
  const commands = await page.getByRole("tabpanel").locator("pre").innerText();

  const oobi = commands.match(/--oobi (\S+)/)?.[1];
  const recipient = commands.match(/--recipient (\S+)/)?.[1];
  const token = commands.match(/--message (\S+)/)?.[1];

  if (!oobi || !recipient || !token) {
    throw new Error(`Presentation commands were missing an oobi, recipient or token:\n${commands}`);
  }

  // Resolving the oobi the page printed, exactly as a holder copying the block would.
  await kli.oobi.resolve(oobi, "verifier");
  await kli.ipex.grant({ said, recipient, message: token });

  await expect(page.getByText("Credential presented. The result is below.")).toBeVisible();
  await expect(page.getByText("Verified", { exact: true })).toBeVisible();
  await expect(page.getByText(said)).toBeVisible();

  // Nothing may fail: the grant carries the issuer KEL and registry events alongside the credential,
  // so every check but the offline-only schema one has what it needs.
  await expect(page.getByText("✗")).toHaveCount(0);
});

test("clears the last result when a new session starts", async ({ page }) => {
  await page.goto("/");
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

  await expect(page.getByText(said)).toBeVisible();

  // The verdict belongs to the presentation that produced it, so asking for a new session must not
  // leave the old result sitting underneath the new instructions.
  await page.getByRole("button", { name: "Present another" }).click();

  await expect(page.getByText(said)).toBeHidden();
  await expect(page.getByText("Verified", { exact: true })).toBeHidden();
  await expect(page.getByText("Waiting for a presentation…")).toBeVisible();
});
