import type { ReactNode } from "react";
import { cx } from "./class-names.ts";
import styles from "./FieldList.module.css";

export function FieldList({ mono = false, children }: { mono?: boolean; children: ReactNode }) {
  return <dl className={cx(styles.list, mono && styles.mono)}>{children}</dl>;
}

interface FieldProps {
  label: ReactNode;
  tone?: "ok" | "bad";
  children: ReactNode;
}

export function Field({ label, tone, children }: FieldProps) {
  return (
    <div className={styles.field}>
      <dt className={styles.label}>{label}</dt>
      <dd className={cx(styles.value, tone && styles[tone])}>{children}</dd>
    </div>
  );
}
