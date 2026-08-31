import { dot, type TestEvent } from "node:test/reporters";

// `@types/node@22` omits `counts.failed`; the runtime emits it.
type Summary = Extract<TestEvent, { type: "test:summary" }>["data"] & { counts: { failed: number } };

function line({ counts, duration_ms }: Summary): string {
  const parts = [`${counts.passed} passed`];
  if (counts.failed > 0) parts.push(`${counts.failed} failed`);
  if (counts.cancelled > 0) parts.push(`${counts.cancelled} cancelled`);
  if (counts.skipped > 0) parts.push(`${counts.skipped} skipped`);
  if (counts.todo > 0) parts.push(`${counts.todo} todo`);

  return `${parts.join(", ")} in ${Math.round(duration_ms)}ms`;
}

/**
 * `dot` with the closing count it does not emit. Two `--test-reporter` flags aimed at one
 * destination write over each other, so the count has to come from inside a single reporter.
 */
export default async function* reporter(source: AsyncGenerator<TestEvent, void>) {
  let run: Summary | undefined;

  // One `test:summary` per file, then one for the whole run — the run's is the one with no `file`.
  async function* passthrough(): AsyncGenerator<TestEvent, void> {
    for await (const event of source) {
      if (event.type === "test:summary" && event.data.file === undefined) {
        run = event.data as Summary;
      }
      yield event;
    }
  }

  yield* dot(passthrough());

  if (run) {
    yield `\n${line(run)}\n`;
  }
}
