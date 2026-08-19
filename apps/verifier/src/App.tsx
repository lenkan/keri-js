import { Alert, Container, Stack, Tabs, Text, Textarea, Title } from "@mantine/core";
import type { CredentialVerification } from "keri";
import { EventIndex, verifyCredentials } from "keri";
import { useCallback, useState } from "react";
import { CredentialResult } from "./CredentialResult.tsx";
import { CommandBlock, Disclosure, Dropzone } from "./components/main.ts";
import { Presentation } from "./Presentation.tsx";

const TRY_IT_INSTALL_COMMANDS = "pip install keri==1.3.3";

const TRY_IT_SETUP_COMMANDS = `kli init --name demo --nopasscode
kli incept --name demo --alias issuer --icount 1 --isith 1 --ncount 1 --nsith 1 --toad 0 --transferable
kli oobi resolve --name demo --oobi https://weboftrust.github.io/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli vc registry incept --name demo --alias issuer --registry-name demo-registry`;

const TRY_IT_CREDENTIAL_COMMANDS = `kli vc create --name demo --alias issuer --registry-name demo-registry \\
  --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao \\
  --recipient "$(kli aid --name demo --alias issuer)" \\
  --data '{"LEI":"1234567890123456789"}'
kli vc export --name demo --alias issuer \\
  --said "$(kli vc list --name demo --alias issuer --said --issued | tail -n 1)" \\
  --full > credential.cesr`;

const CESR_ACCEPT = [".cesr"];

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
    <Container size="md" py="xl">
      <Title order={1}>ACDC Verifier</Title>
      <Text c="dimmed" maw={640} mb="xl">
        Bring a credential as a CESR stream, or have it presented over IPEX — either way it is verified entirely in this
        page.
      </Text>

      <Disclosure summary="Don't have a credential handy? Generate one locally">
        <Stack gap="md">
          <Text>
            Requires Python 3.12+ and keripy's <code>kli</code>:
          </Text>

          <CommandBlock>{TRY_IT_INSTALL_COMMANDS}</CommandBlock>

          <Text>Then create a local identifier with a credential registry:</Text>

          <CommandBlock>{TRY_IT_SETUP_COMMANDS}</CommandBlock>

          <Text>
            Already have a <code>demo</code> keystore? Delete <code>~/.keri</code>, or change <code>--name demo</code>.
          </Text>

          <Text>Issue a credential — repeat to create more:</Text>

          <CommandBlock>{TRY_IT_CREDENTIAL_COMMANDS}</CommandBlock>

          <Text>
            Writes <code>credential.cesr</code>. Drop it below, or paste it in.
          </Text>
        </Stack>
      </Disclosure>

      <Tabs defaultValue="stream" mt="md">
        <Tabs.List>
          <Tabs.Tab value="stream">Bring a stream</Tabs.Tab>
          <Tabs.Tab value="ipex">Present over IPEX</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="stream">
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
        </Tabs.Panel>

        <Tabs.Panel value="ipex">
          <Presentation onStream={verify} />
        </Tabs.Panel>
      </Tabs>

      {state.kind === "error" && <Alert>Could not read the stream: {state.message}</Alert>}

      {state.kind === "done" && state.results.length === 0 && <Alert>No credential found in that stream.</Alert>}

      {state.kind === "done" && state.results.map((result) => <CredentialResult key={result.said} result={result} />)}
    </Container>
  );
}
