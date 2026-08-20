import { Alert, Button, Group, Loader, SegmentedControl, Stack, Text, TextInput } from "@mantine/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { CommandBlock, Disclosure } from "../components/main.ts";
import { type Identity, IdentityCard } from "../IdentityCard.tsx";

const POLL_MS = 2000;

interface Session {
  token: string;
}

type Phase =
  | { kind: "starting" }
  | { kind: "error"; message: string }
  | { kind: "supply-kel"; session: Session }
  | { kind: "challenged"; session: Session; aid: string; words: string[]; lastError?: string }
  | { kind: "authenticated"; identity: Identity };

interface LoginStatus {
  phase: "challenged" | "authenticated";
  aid?: string;
  words?: string[];
  error?: string;
  identity?: Identity;
}

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

/** Logs a KERIpy-controlled AID into the portal: KEL in, challenge words out, signed response back. */
export function LoginMode() {
  const [phase, setPhase] = useState<Phase>({ kind: "starting" });
  const [intake, setIntake] = useState<"push" | "oobi">("push");
  const [oobiUrl, setOobiUrl] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const started = useRef(false);

  const start = useCallback(async () => {
    setPhase({ kind: "starting" });
    setSubmitError(null);
    setOobiUrl("");

    try {
      const response = await fetch("/api/login/sessions", { method: "POST" });
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }
      setPhase({ kind: "supply-kel", session: (await response.json()) as Session });
    } catch (cause) {
      setPhase({ kind: "error", message: cause instanceof Error ? cause.message : String(cause) });
    }
  }, []);

  // Once per mount, not once per effect run: the tab keeps this mounted but
  // tears effects down while hidden, and a fresh session on the way back would
  // orphan the commands already copied out of here.
  useEffect(() => {
    if (started.current) {
      return;
    }

    started.current = true;
    void start();
  }, [start]);

  const token = phase.kind === "supply-kel" || phase.kind === "challenged" ? phase.session.token : null;

  useEffect(() => {
    if (!token) {
      return;
    }

    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;

    async function poll() {
      try {
        const response = await fetch(`/api/login/sessions/${token}`, { signal: controller.signal });

        if (response.status === 200) {
          const status = (await response.json()) as LoginStatus;

          if (status.phase === "authenticated" && status.identity) {
            setPhase({ kind: "authenticated", identity: status.identity });
            return;
          }

          if (status.phase === "challenged" && status.aid && status.words) {
            const { aid, words, error } = status;
            // Keep polling, but only re-render when the server actually moved.
            setPhase((current) =>
              current.kind === "challenged" &&
              current.aid === aid &&
              current.words.join(" ") === words.join(" ") &&
              current.lastError === error
                ? current
                : { kind: "challenged", session: { token: token as string }, aid, words, lastError: error },
            );
          }
        } else if (response.status !== 204) {
          setPhase({ kind: "error", message: `Server returned ${response.status}` });
          return;
        }
      } catch (cause) {
        if (controller.signal.aborted) {
          return;
        }
        setPhase({ kind: "error", message: cause instanceof Error ? cause.message : String(cause) });
        return;
      }

      timer = setTimeout(poll, POLL_MS);
    }

    void poll();

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [token]);

  const submitOobi = useCallback(async () => {
    if (!token) {
      return;
    }

    setSubmitError(null);

    try {
      const response = await fetch(`/api/login/sessions/${token}/oobi`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: oobiUrl }),
      });
      const body = (await response.json()) as { aid?: string; words?: string[]; error?: string };

      if (!response.ok || !body.aid || !body.words) {
        setSubmitError(body.error ?? `Server returned ${response.status}`);
        return;
      }

      setPhase({ kind: "challenged", session: { token }, aid: body.aid, words: body.words });
    } catch (cause) {
      setSubmitError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [token, oobiUrl]);

  if (phase.kind === "error") {
    return (
      <Stack gap="md" mt="md">
        <Alert color="red">Could not reach the portal: {phase.message}</Alert>
        <Group>
          <Button onClick={() => void start()}>Try again</Button>
        </Group>
      </Stack>
    );
  }

  if (phase.kind === "starting") {
    return (
      <Group mt="md" gap="xs">
        <Loader size="sm" />
        <Text>Starting a session…</Text>
      </Group>
    );
  }

  if (phase.kind === "authenticated") {
    return <IdentityCard identity={phase.identity} onLogout={() => void start()} />;
  }

  if (phase.kind === "challenged") {
    return (
      <Stack gap="md" mt="md">
        <Text>
          Found your key event log — <Text span ff="monospace">{`${phase.aid.slice(0, 12)}…`}</Text> is challenged. Sign
          these twelve words to prove you hold its keys. First resolve this portal so <code>kli</code> knows where to
          send, then respond:
        </Text>

        <CommandBlock>{respondCommands(phase.words)}</CommandBlock>

        {phase.lastError && <Alert color="yellow">{phase.lastError}</Alert>}

        <Group gap="xs">
          <Loader size="sm" />
          <Text>Waiting for your signed response — watch this page, not the terminal.</Text>
        </Group>

        <Group>
          <Button variant="default" onClick={() => void start()}>
            Start over
          </Button>
        </Group>
      </Stack>
    );
  }

  return (
    <Stack gap="md" mt="md">
      <Text maw={640}>
        Log in with a KERI identifier — no password, no email. Your <code>kli</code> keystore holds the keys; this
        portal only ever sees your public key event log and a signed challenge.
      </Text>

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
          <Text>Export your key event log straight into this session:</Text>
          <CommandBlock>{pushCommand(phase.session.token)}</CommandBlock>
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
            <Button onClick={() => void submitOobi()} disabled={!oobiUrl}>
              Fetch
            </Button>
          </Group>
        </>
      )}

      {submitError && <Alert color="red">{submitError}</Alert>}
    </Stack>
  );
}
