import type { ComponentProps } from "react";
import { cx } from "./class-names.ts";
import styles from "./TextArea.module.css";

export function TextArea({ className, ...props }: ComponentProps<"textarea">) {
  return <textarea {...props} className={cx(styles.textarea, className)} />;
}
