import type { ReactNode } from "react";
import styles from "./Badge.module.css";
import { cx } from "./class-names.ts";

export type Tone = "neutral" | "ok" | "bad";

const TONES: Record<Tone, string | undefined> = {
  neutral: undefined,
  ok: styles.ok,
  bad: styles.bad,
};

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={cx(styles.badge, TONES[tone])}>{children}</span>;
}
