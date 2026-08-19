import { Group, Stack, Text, ThemeIcon } from "@mantine/core";
import type { ReactNode } from "react";
import { TONE_COLORS, type Tone } from "./tone.ts";

export type CheckState = "passed" | "failed" | "skipped" | "not-applicable" | "unchecked";

const STATES: Record<CheckState, { mark: string; tone: Tone; dimmed?: boolean }> = {
  passed: { mark: "✓", tone: "ok" },
  failed: { mark: "✗", tone: "bad" },
  skipped: { mark: "–", tone: "neutral", dimmed: true },
  "not-applicable": { mark: "–", tone: "neutral", dimmed: true },
  unchecked: { mark: "?", tone: "warn", dimmed: true },
};

export function CheckList({ children }: { children: ReactNode }) {
  return <Stack gap={4}>{children}</Stack>;
}

interface CheckItemProps {
  state: CheckState;
  label: ReactNode;
  detail?: ReactNode;
}

export function CheckItem({ state, label, detail }: CheckItemProps) {
  const { mark, tone, dimmed } = STATES[state];

  return (
    <Group gap="xs" wrap="nowrap">
      <ThemeIcon variant="light" color={TONE_COLORS[tone]} size="sm" radius="xl">
        {mark}
      </ThemeIcon>
      <Text size="sm" c={dimmed ? "dimmed" : undefined}>
        {label}
      </Text>
      {detail && (
        <Text size="xs" c="dimmed">
          {detail}
        </Text>
      )}
    </Group>
  );
}
