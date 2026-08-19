import type { MantineColor } from "@mantine/core";

export type Tone = "ok" | "bad" | "neutral" | "warn";

export const TONE_COLORS: Record<Tone, MantineColor> = {
  ok: "green",
  bad: "red",
  neutral: "gray",
  warn: "yellow",
};
