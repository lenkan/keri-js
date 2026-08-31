import { dot, type TestEvent } from "node:test/reporters";

/**
 * `dot` with a closing count. Two `--test-reporter` flags pointed at the same destination race and
 * the second one's output is dropped, so the count has to come from inside a single reporter.
 */

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

export default async function* reporter(source: AsyncGenerator<TestEvent, void>) {
  let run: Summary | undefined;

  // One `test:summary` per file, then one for the whole run — the run's is the one with no `file`.
  async function* tap(): AsyncGenerator<TestEvent, void> {
    for await (const event of source) {
      if (event.type === "test:summary" && event.data.file === undefined) {
        run = event.data as Summary;
      }
      yield event;
    }
  }

  yield* dot(tap());

  if (run) {
    yield `\n${line(run)}\n`;
  }
}
