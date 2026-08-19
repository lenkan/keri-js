import { BASE_URL } from "../playwright.config.ts";

const TIMEOUT = 30000;
const INTERVAL = 500;

// The dev server is started outside the test run, so the suite waits for it rather than owning it.
export default async function globalSetup(): Promise<void> {
  const deadline = Date.now() + TIMEOUT;

  while (Date.now() < deadline) {
    try {
      await fetch(BASE_URL);
      return;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, INTERVAL));
  }

  throw new Error(
    `${BASE_URL} did not answer within ${TIMEOUT / 1000}s. Start the verifier first ` +
      `("pnpm run dev:verifier"), or point E2E_BASE_URL somewhere else.`,
  );
}
