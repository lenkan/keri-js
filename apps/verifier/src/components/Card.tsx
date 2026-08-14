import type { ReactNode } from "react";
import styles from "./Card.module.css";

export function Card({ children }: { children: ReactNode }) {
  return <article className={styles.card}>{children}</article>;
}
