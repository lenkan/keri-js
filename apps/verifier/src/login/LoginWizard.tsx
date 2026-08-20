import { Alert, Button, Group, Loader, SegmentedControl, Stack, Text, TextInput } from "@mantine/core";
import { useState } from "react";
import { CommandBlock, Disclosure } from "../components/main.ts";
import type { Login } from "./useLogin.ts";

const SETUP_COMMANDS = `pip install keri==1.3.3
kli init --name demo --nopasscode
kli incept --name demo --alias issuer --icount 1 --isith 1 --ncount 1 --nsith 1 --toad 0 --transferable`;

function pushCommand(token: string): string {
  return `kli export --name demo --alias issuer | curl -fsS -X POST \\
  --data-binary @- ${window.location.origin}/api/login/sessions/${token}/kel`;
}

function respondCommands(words: string[]): string {
  return `kli oobi resolve --name demo --oobi ${window.location.origin}/oobi --oobi-alias portal
kli challenge respond --name demo --alias issuer \\
  --words "${words.join(" ")}" \\
  --recipient portal`;
}

/** The steps from "stranger" to "authenticated": KEL in, challenge words out, signed response back. */
export function LoginWizard({ phase, restart, submitOobi }: Login) {
  const [intake, setIntake] = useState<"push" | "oobi">("push");
  const [oobiUrl, setOobiUrl] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);

  if (phase.kind === "error") {
    return (
      <Stack gap="md" mt="md">
        <Alert color="red">Could not reach the portal: {phase.message}</Alert>
        <Group>
          <Button onClick={restart}>Try again</Button>
        </Group>
      </Stack>
    );
  }

  if (phase.kind === "resuming" || phase.kind === "authenticated") {
    return (
      <Group mt="md" gap="xs">
        <Loader size="sm" />
        <Text>Starting a session…</Text>
      </Group>
    );
  }

  if (phase.kind === "challenged") {
    return (
      <Stack gap="md" mt="md">
        <Text>
          Key event log received for{" "}
          <Text span ff="monospace">
            {`${phase.aid.slice(0, 12)}…`}
          </Text>
          . Two commands left: the first resolves this portal as a <code>kli</code> contact, the second signs the
          challenge words and sends the response.
        </Text>

        <CommandBlock>{respondCommands(phase.words)}</CommandBlock>

        {phase.lastError && <Alert color="yellow">{phase.lastError}</Alert>}

        <Group gap="xs">
          <Loader size="sm" />
          <Text>
            Waiting for the signed response. The result appears here — <code>kli</code> does not check the reply.
          </Text>
        </Group>

        <Group>
          <Button variant="default" onClick={restart}>
            Start over
          </Button>
        </Group>
      </Stack>
    );
  }

  return (
    <Stack gap="md" mt="md">
      <Disclosure summary="No identifier yet? Create one locally">
        <Stack gap="md">
          <Text>
            Requires Python 3.12+ and keripy's <code>kli</code>. Witnesses are not needed to log in:
          </Text>
          <CommandBlock>{SETUP_COMMANDS}</CommandBlock>
        </Stack>
      </Disclosure>

      <SegmentedControl
        value={intake}
        onChange={(value) => setIntake(value as "push" | "oobi")}
        data={[
          { label: "Push your KEL", value: "push" },
          { label: "Fetch from an OOBI", value: "oobi" },
        ]}
        maw={320}
      />

      {intake === "push" ? (
        <>
          <Text>Export your key event log into this session:</Text>
          <CommandBlock>{pushCommand(phase.token)}</CommandBlock>
          <Group gap="xs">
            <Loader size="sm" />
            <Text>Waiting for your key event log…</Text>
          </Group>
        </>
      ) : (
        <>
          <Text>Paste an OOBI URL that serves your key event log — a witness OOBI works:</Text>
          <Group align="end">
            <TextInput
              value={oobiUrl}
              onChange={(event) => setOobiUrl(event.currentTarget.value)}
              placeholder="https://witness.example/oobi/EAbc…"
              flex={1}
            />
            <Button
              onClick={() => {
                setSubmitError(null);
                void submitOobi(oobiUrl).then(setSubmitError);
              }}
              disabled={!oobiUrl}
            >
              Fetch
            </Button>
          </Group>
        </>
      )}

      {submitError && <Alert color="red">{submitError}</Alert>}
    </Stack>
  );
}
