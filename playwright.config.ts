import { defineConfig, devices } from "@playwright/test";

export const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:5173";

export default defineConfig({
  testDir: "./test_e2e",
  globalSetup: "./test_e2e/global-setup.ts",
  // `kli` mints a credential in a `beforeAll`, which takes longer than the default budget.
  timeout: 60_000,
  workers: 1,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: { baseURL: BASE_URL, trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: devices["Desktop Chrome"] }],
});
