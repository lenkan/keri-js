import { Textarea } from "@mantine/core";
import { useCallback } from "react";
import { Disclosure, Dropzone } from "../components/main.ts";
import { useVerification, VerificationResult } from "../Verification.tsx";

const CESR_ACCEPT = [".cesr"];

/** Takes a credential the visitor already has, as a dropped file or pasted text. */
export function StreamMode() {
  const { state, verify } = useVerification();

  const onFile = useCallback(
    (file: File) => {
      void file.arrayBuffer().then((buffer) => verify(new Uint8Array(buffer)));
    },
    [verify],
  );

  return (
    <>
      <Dropzone onFile={onFile} accept={CESR_ACCEPT}>
        Drop a .cesr file here
      </Dropzone>

      <Disclosure summary="Paste a stream instead">
        {/* Verification is synchronous and costs ~13ms per credential, so it runs on
            paste/blur rather than on every keystroke. */}
        <Textarea
          rows={6}
          placeholder='{"v":"KERI10JSON…'
          onPaste={(event) => {
            const text = event.clipboardData.getData("text").trim();
            if (text) {
              void verify(text);
            }
          }}
          onBlur={(event) => {
            const text = event.target.value.trim();
            if (text) {
              void verify(text);
            }
          }}
        />
      </Disclosure>

      <VerificationResult state={state} />
    </>
  );
}
