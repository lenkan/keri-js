import { useState } from "react";
import styles from "./CommandBlock.module.css";

export function CommandBlock({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);

  const onCopy = () => {
    if (!navigator.clipboard) {
      return;
    }
    void navigator.clipboard.writeText(children).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className={styles.block}>
      <button type="button" className={styles.copy} onClick={onCopy}>
        {copied ? "Copied" : "Copy"}
      </button>
      <pre className={styles.pre}>
        <code>{children}</code>
      </pre>
    </div>
  );
}
