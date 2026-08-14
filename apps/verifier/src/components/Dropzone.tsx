import type { DragEvent, ReactNode } from "react";
import { useCallback, useState } from "react";
import { cx } from "./class-names.ts";
import styles from "./Dropzone.module.css";

interface DropzoneProps {
  onFile: (file: File) => void;
  accept?: string;
  browseLabel?: string;
  children: ReactNode;
}

export function Dropzone({ onFile, accept, browseLabel = "or choose a file", children }: DropzoneProps) {
  const [dragging, setDragging] = useState(false);

  const onDrop = useCallback(
    (event: DragEvent) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files[0];
      if (file) {
        onFile(file);
      }
    },
    [onFile],
  );

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: drag and drop enhances the file input below, which stays the accessible path
    <section
      className={cx(styles.dropzone, dragging && styles.dragging)}
      onDrop={onDrop}
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
    >
      <p className={styles.prompt}>{children}</p>
      <label className={styles.browse}>
        {browseLabel}
        <input
          type="file"
          accept={accept}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) {
              onFile(file);
            }
          }}
        />
      </label>
    </section>
  );
}
