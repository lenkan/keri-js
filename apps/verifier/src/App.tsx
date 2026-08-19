import type { CredentialVerification } from "keri";
import { EventIndex, verifyCredentials } from "keri";
import { useCallback, useState } from "react";
import styles from "./App.module.css";
import { CredentialResult } from "./CredentialResult.tsx";
import { CommandBlock, Disclosure, Dropzone, ErrorMessage, TextArea } from "./components/main.ts";

const TRY_IT_COMMANDS = `pip install keri==1.3.3

kli init --name demo --nopasscode
kli incept --name demo --alias issuer --icount 1 --isith 1 --ncount 1 --nsith 1 --toad 0 --transferable
kli oobi resolve --name demo --oobi https://weboftrust.github.io/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli vc registry incept --name demo --alias issuer --registry-name demo-registry
kli vc create --name demo --alias issuer --registry-name demo-registry \\
  --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao \\
  --recipient "$(kli aid --name demo --alias issuer)" \\
  --data '{"LEI":"1234567890123456789"}'
kli vc export --name demo --alias issuer \\
  --said "$(kli vc list --name demo --alias issuer --said --issued)" \\
  --full > credential.cesr`;

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

      <Disclosure summary="Don't have a credential handy? Generate one locally">
        <p className={styles.tryItLede}>
          Requires Python 3.9+ and a Bash-compatible shell. These commands install keripy's <code>kli</code> CLI and
          issue a small, self-signed credential entirely on your own machine — no witnesses, and no network calls except
          a one-time fetch of the public schema document.
        </p>

        <CommandBlock>{TRY_IT_COMMANDS}</CommandBlock>

        <p className={styles.tryItLede}>
          If you've run this before, the second run fails at <code>kli init</code> because <code>~/.keri</code> still
          has the <code>demo</code> keystore — delete it or change every <code>--name demo</code> to something new.
        </p>

        <p className={styles.tryItLede}>
          That writes <code>credential.cesr</code> in your working directory. Drop it in the box below, or paste its
          contents into the text area.
        </p>
      </Disclosure>

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
