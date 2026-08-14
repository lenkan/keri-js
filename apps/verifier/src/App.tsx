import { useCallback, useState } from "react";
import type { CredentialVerification } from "../../../src/core/main.ts";
import { EventIndex, verifyCredentials } from "../../../src/core/main.ts";
import { CredentialResult } from "./CredentialResult.tsx";

type State =
  | { kind: "idle" }
  | { kind: "error"; message: string }
  | { kind: "done"; results: CredentialVerification[] };

export function App() {
  const [state, setState] = useState<State>({ kind: "idle" });
  const [dragging, setDragging] = useState(false);

  const verify = useCallback(async (input: Uint8Array | string) => {
    try {
      setState({ kind: "done", results: verifyCredentials(await EventIndex.parse(input)) });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : String(error) });
    }
  }, []);

  const onDrop = useCallback(
    async (event: React.DragEvent) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files[0];
      if (file) {
        await verify(new Uint8Array(await file.arrayBuffer()));
      }
    },
    [verify],
  );

  return (
    <main>
      <h1>ACDC Verifier</h1>
      <p className="lede">
        Drop a CESR stream containing a credential, its issuer's key event log, and the registry events. Everything is
        verified in this page — no network, no server.
      </p>

      {/* biome-ignore lint/a11y/noStaticElementInteractions: drag and drop enhances the file input below, which stays the accessible path */}
      <section
        className={`dropzone${dragging ? " dragging" : ""}`}
        onDrop={onDrop}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
      >
        <p>Drop a .cesr file here</p>
        <label className="file">
          or choose a file
          <input
            type="file"
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (file) {
                await verify(new Uint8Array(await file.arrayBuffer()));
              }
            }}
          />
        </label>
      </section>

      <details className="paste">
        <summary>Paste a stream instead</summary>
        {/* Verification is synchronous and costs ~13ms per credential, so it runs on
            commit rather than on every keystroke. */}
        <textarea
          rows={6}
          placeholder='{"v":"KERI10JSON…'
          onBlur={(event) => {
            const text = event.target.value.trim();
            if (text) {
              void verify(text);
            }
          }}
        />
      </details>

      {state.kind === "error" && <p className="error">Could not read the stream: {state.message}</p>}

      {state.kind === "done" && state.results.length === 0 && (
        <p className="error">No credential found in that stream.</p>
      )}

      {state.kind === "done" && state.results.map((result) => <CredentialResult key={result.said} result={result} />)}
    </main>
  );
}
