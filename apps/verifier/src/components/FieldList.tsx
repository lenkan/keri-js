import { Group, Stack, Text } from "@mantine/core";
import type { CSSProperties, ReactNode } from "react";
import { TONE_COLORS, type Tone } from "./tone.ts";

export function FieldList({ children }: { children: ReactNode }) {
  return <Stack gap="xs">{children}</Stack>;
}

interface FieldProps {
  label: ReactNode;
  mono?: boolean;
  tone?: Tone;
  children: ReactNode;
}

const VALUE_STYLE: CSSProperties = { wordBreak: "break-all" };

export function Field({ label, mono = false, tone, children }: FieldProps) {
  return (
    <Group gap="md" wrap="nowrap" align="baseline">
      <Text size="sm" c="dimmed" miw={120}>
        {label}
      </Text>
      <Text size="sm" ff={mono ? "monospace" : undefined} c={tone && TONE_COLORS[tone]} style={VALUE_STYLE}>
        {children}
      </Text>
    </Group>
  );
}
