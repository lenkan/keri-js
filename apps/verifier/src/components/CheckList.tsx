import type { ReactNode } from "react";
import styles from "./CheckList.module.css";
import { cx } from "./class-names.ts";

export type CheckState = "passed" | "failed" | "skipped" | "not-applicable" | "unchecked";

const MARKS: Record<CheckState, string> = {
  passed: "✓",
  failed: "✗",
  skipped: "–",
  "not-applicable": "–",
  unchecked: "?",
};

const TONES: Record<CheckState, string | undefined> = {
  passed: styles.passed,
  failed: styles.failed,
  skipped: styles.dimmed,
  "not-applicable": styles.dimmed,
  unchecked: cx(styles.unchecked, styles.dimmed),
};

export function CheckList({ children }: { children: ReactNode }) {
  return <ul className={styles.list}>{children}</ul>;
}

interface CheckItemProps {
  state: CheckState;
  label: ReactNode;
  detail?: ReactNode;
}

export function CheckItem({ state, label, detail }: CheckItemProps) {
  return (
    <li className={cx(styles.item, TONES[state])}>
      <span className={styles.mark}>{MARKS[state]}</span>
      <span className={styles.label}>{label}</span>
      {detail && <span className={styles.detail}>{detail}</span>}
    </li>
  );
}
