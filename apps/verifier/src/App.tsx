import type { CredentialVerification } from "keri";
import { EventIndex, verifyCredentials } from "keri";
import { useCallback, useState } from "react";
import styles from "./App.module.css";
import { CredentialResult } from "./CredentialResult.tsx";
import { Disclosure, Dropzone, ErrorMessage, TextArea } from "./components/main.ts";

type State =
  | { kind: "idle" }
  | { kind: "error"; message: string }
  | { kind: "done"; results: CredentialVerification[] };

export function App() {
  const [state, setState] = useState<State>({ kind: "idle" });

  const verify = useCallback(async (input: Uint8Array | string) => {
    try {
      setState({ kind: "done", results: verifyCredentials(await EventIndex.parse(input)) });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : String(error) });
    }
  }, []);

  const onFile = useCallback(
    (file: File) => {
      void file.arrayBuffer().then((buffer) => verify(new Uint8Array(buffer)));
    },
    [verify],
  );

  return (
    <main className={styles.page}>
      <h1 className={styles.title}>ACDC Verifier</h1>
      <p className={styles.lede}>
        Drop a CESR stream containing a credential, its issuer's key event log, and the registry events. Everything is
        verified in this page — no network, no server.
      </p>

      <Dropzone onFile={onFile} accept=".cesr">
        Drop a .cesr file here
      </Dropzone>

      <Disclosure summary="Paste a stream instead">
        {/* Verification is synchronous and costs ~13ms per credential, so it runs on
            commit rather than on every keystroke. */}
        <TextArea
          rows={6}
          placeholder='{"v":"KERI10JSON…'
          onBlur={(event) => {
            const text = event.target.value.trim();
            if (text) {
              void verify(text);
            }
          }}
        />
      </Disclosure>

      {state.kind === "error" && <ErrorMessage>Could not read the stream: {state.message}</ErrorMessage>}

      {state.kind === "done" && state.results.length === 0 && (
        <ErrorMessage>No credential found in that stream.</ErrorMessage>
      )}

      {state.kind === "done" && state.results.map((result) => <CredentialResult key={result.said} result={result} />)}
    </main>
  );
}
