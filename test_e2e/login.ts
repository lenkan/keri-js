import { expect, type Page } from "@playwright/test";
import { BASE_URL } from "../playwright.config.ts";
import type { KERIPy } from "../test_utils/keripy.ts";

/**
 * The whole app sits behind the login gate, so every spec starts here. The
 * worker environment comes up after vite starts answering, so the gate is also
 * where the suite absorbs that gap.
 */
export async function waitForApi(): Promise<void> {
  const deadline = Date.now() + 30_000;

  while (Date.now() < deadline) {
    const ok = (await fetch(`${BASE_URL}/api/login/sessions`, { method: "POST" }).catch(() => null))?.ok === true;
    if (ok) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error(`${BASE_URL}/api/login/sessions did not answer. Start the verifier ("pnpm run dev:verifier").`);
}

/**
 * Logs `kli` into the portal by executing the commands the page prints —
 * reading them back out is itself an assertion that the page printed usable
 * ones. The KEL push runs from here rather than through a shell, but hits the
 * same endpoint the printed curl command names.
 */
export async function login(page: Page, kli: KERIPy): Promise<void> {
  await page.goto("/");

  const push = await page.locator("pre").filter({ hasText: "curl -fsS" }).innerText();
  const token = push.match(/\/api\/login\/sessions\/([A-Za-z0-9]+)\/kel/)?.[1];
  if (!token) {
    throw new Error(`The push command carried no session token:\n${push}`);
  }

  const submitted = await fetch(`${BASE_URL}/api/login/sessions/${token}/kel`, {
    method: "POST",
    body: await kli.export(),
  });
  if (!submitted.ok) {
    throw new Error(`KEL push failed with ${submitted.status}: ${await submitted.text()}`);
  }

  const respond = await page.locator("pre").filter({ hasText: "challenge respond" }).innerText();
  const oobi = respond.match(/--oobi (\S+)/)?.[1];
  const words = respond.match(/--words "([^"]+)"/)?.[1];
  if (!oobi || !words) {
    throw new Error(`The respond commands were missing an oobi or words:\n${respond}`);
  }

  await kli.oobi.resolve(oobi, "portal");
  await kli.challenge.respond({ words: words.split(" "), recipient: "portal" });

  await expect(page.getByText("Logged in", { exact: true })).toBeVisible({ timeout: 15_000 });
}
