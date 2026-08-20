import { expect, type Page, test } from "@playwright/test";
import type { KERIPy } from "../test_utils/keripy.ts";
import { issueCredential, QVI_SCHEMA, REGISTRY_NAME } from "./credential.ts";
import { login, waitForApi } from "./login.ts";

// Mirrors CHECK_LABELS in apps/verifier/src/checks.ts, plus the presentation-only
// issuee check. Duplicated rather than imported: for a test that asserts on
// rendered text, the strings are the contract.
const CHECK_LABELS = [
  "Credential SAID",
  "Section SAIDs",
  "Issuer key event log",
  "Registry inception",
  "Registry anchored in issuer KEL",
  "Issuance event",
  "Issuance anchored in issuer KEL",
  "Revocation",
  "Linked credentials",
  "Schema",
  "Issued to you",
];

let said: string;
let kli: KERIPy;

test.beforeAll(async () => {
  await waitForApi();

  ({ said, kli } = await issueCredential());
});

/**
 * Logs in and presents a credential by running the command the page prints —
 * reading it back out is itself an assertion that the page printed a usable one.
 */
async function present(page: Page, presentedSaid: string): Promise<void> {
  await login(page, kli);

  const command = await page.locator("pre").filter({ hasText: "ipex grant" }).innerText();

  const recipient = command.match(/--recipient (\S+)/)?.[1];
  const token = command.match(/--message (\S+)/)?.[1];

  if (!recipient || !token) {
    throw new Error(`The presentation command was missing a recipient or token:\n${command}`);
  }

  await kli.ipex.grant({ said: presentedSaid, recipient, message: token });
}

test("verifies a credential presented by its issuee", async ({ page }) => {
  await present(page, said);

  await expect(page.getByText("Credential presented. The result is below.")).toBeVisible();
  await expect(page.getByText("Verified", { exact: true })).toBeVisible();
  await expect(page.getByText(said)).toBeVisible();
  // Exact: the same LEI appears inside the "issue one to yourself" commands further up the page.
  await expect(page.getByText("1234567890123456789", { exact: true })).toBeVisible();

  // "Schema" is both a check label and a field label, so the first match is the assertion.
  for (const label of CHECK_LABELS) {
    await expect(page.getByText(label, { exact: true }).first()).toBeVisible();
  }

  // The grant carries the issuer KEL and registry events alongside the credential, so every check
  // but the offline-only schema one has what it needs — and the issuee is the logged-in AID.
  await expect(page.getByText("✗")).toHaveCount(0);
});

test("rejects a credential issued to someone else", async ({ page }) => {
  // A second AID in the same keystore: the credential verifies, but its issuee
  // is not the AID that logged in.
  await kli.incept({ alias: "other", toad: 0 });
  await kli.vc.create({
    registryName: REGISTRY_NAME,
    schema: QVI_SCHEMA,
    recipient: await kli.aid({ alias: "other" }),
    data: { LEI: "9876543210987654321" },
  });
  const otherSaid = (await kli.vc.saids()).at(-1);
  if (!otherSaid) {
    throw new Error("kli vc list reported no issued credential");
  }

  await present(page, otherSaid.trim());

  await expect(page.getByText("Not issued to you", { exact: true })).toBeVisible();
  await expect(page.getByText("Verified", { exact: true })).toBeHidden();
});

test("clears the last result when a new session starts", async ({ page }) => {
  await present(page, said);

  await expect(page.getByText(said)).toBeVisible();

  // The verdict belongs to the presentation that produced it, so asking for a new session must not
  // leave the old result sitting underneath the new instructions.
  await page.getByRole("button", { name: "Present another" }).click();

  await expect(page.getByText(said)).toBeHidden();
  await expect(page.getByText("Verified", { exact: true })).toBeHidden();
  await expect(page.getByText("Waiting for a presentation…")).toBeVisible();
});
