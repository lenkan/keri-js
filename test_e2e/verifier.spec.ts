import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import { issueCredential } from "./credential.ts";

// Mirrors CHECK_LABELS in apps/verifier/src/checks.ts. Duplicated rather than imported: for a test
// that asserts on rendered text, the strings are the contract.
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
];

const ALICE_KEL = fileURLToPath(new URL("../fixtures/alice.cesr", import.meta.url));

let said: string;
let stream: string;
let credentialFile: string;
let garbageFile: string;

test.beforeAll(async () => {
  const dir = await mkdtemp(join(tmpdir(), "keri-e2e-"));

  ({ said, stream } = await issueCredential());

  credentialFile = join(dir, "credential.cesr");
  await writeFile(credentialFile, stream);

  // The dropzone filters on the .cesr extension before the app sees the file, so junk still needs
  // the right name to reach the parser.
  garbageFile = join(dir, "garbage.cesr");
  await writeFile(garbageFile, "not a cesr stream at all");
});

test("verifies a credential issued by kli", async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles(credentialFile);

  await expect(page.getByText("Verified", { exact: true })).toBeVisible();
  await expect(page.getByText("issued", { exact: true })).toBeVisible();
  await expect(page.getByText(said)).toBeVisible();
  // Exact: the same LEI appears inside the "generate one locally" commands further up the page.
  await expect(page.getByText("1234567890123456789", { exact: true })).toBeVisible();

  // "Schema" is both a check label and a field label, so the first match is the assertion.
  for (const label of CHECK_LABELS) {
    await expect(page.getByText(label, { exact: true }).first()).toBeVisible();
  }

  // The schema check reports "unchecked" offline, so the assertion is that nothing failed rather
  // than that every check passed.
  await expect(page.getByText("✗")).toHaveCount(0);
});

test("verifies the same credential pasted as text", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Paste a stream instead" }).click();

  const textarea = page.getByRole("textbox");
  await textarea.fill(stream);
  await textarea.blur();

  await expect(page.getByText("Verified", { exact: true })).toBeVisible();
  await expect(page.getByText(said)).toBeVisible();
});

test("reports a stream that carries no credential", async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles(ALICE_KEL);

  await expect(page.getByText("No credential found in that stream.")).toBeVisible();
});

test("reports a stream it cannot parse", async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles(garbageFile);

  await expect(page.getByText("Could not read the stream:")).toBeVisible();
});
