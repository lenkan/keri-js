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

const resolved = new Set<string>();

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
  const oobi = push.match(/--oobi (\S+)/)?.[1];
  if (!token || !oobi) {
    throw new Error(`The first step's commands were missing a session token or oobi:\n${push}`);
  }

  // Resolving updates one `portal` contact in place, so once per keystore is
  // enough — and each call is a `kli` subprocess.
  const contact = `${kli.name}:${oobi}`;
  if (!resolved.has(contact)) {
    await kli.oobi.resolve(oobi, "portal");
    resolved.add(contact);
  }

  const submitted = await fetch(`${BASE_URL}/api/login/sessions/${token}/kel`, {
    method: "POST",
    body: await kli.export(),
  });
  if (!submitted.ok) {
    throw new Error(`KEL push failed with ${submitted.status}: ${await submitted.text()}`);
  }

  const respond = await page.locator("pre").filter({ hasText: "challenge respond" }).innerText();
  const words = respond.match(/--words "([^"]+)"/)?.[1];
  if (!words) {
    throw new Error(`The respond command was missing words:\n${respond}`);
  }

  await kli.challenge.respond({ words: words.split(" "), recipient: "portal" });

  await expect(page.getByText("Logged in", { exact: true })).toBeVisible({ timeout: 15_000 });
}
