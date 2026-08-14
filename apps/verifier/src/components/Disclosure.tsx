import type { ReactNode } from "react";
import styles from "./Disclosure.module.css";

export function Disclosure({ summary, children }: { summary: ReactNode; children: ReactNode }) {
  return (
    <details className={styles.disclosure}>
      <summary>{summary}</summary>
      {children}
    </details>
  );
}
