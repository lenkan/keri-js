import { Alert, Button, Group, Loader, Stack, Text } from "@mantine/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { CommandBlock } from "../components/main.ts";
import { useVerification, VerificationResult } from "../Verification.tsx";

const POLL_MS = 2000;

interface Session {
  token: string;
  aid: string;
  oobi: string;
}

// One lifecycle rather than three booleans, so the render has no combination to
// second-guess and a stale verdict cannot outlive the session that produced it.
type Phase =
  | { kind: "starting" }
  | { kind: "error"; message: string }
  | { kind: "waiting"; session: Session }
  | { kind: "delivered" };

function commands({ token, aid, oobi }: Session): string {
  return `kli oobi resolve --name demo --oobi ${oobi} --oobi-alias verifier
kli ipex grant --name demo --alias issuer \\
  --said "$(kli vc list --name demo --alias issuer --said --issued | tail -n 1)" \\
  --recipient ${aid} \\
  --message ${token}`;
}

/** Receives a credential over IPEX: the holder grants it to the session this component opens. */
export function IpexMode() {
  const { state, verify, reset } = useVerification();
  const [phase, setPhase] = useState<Phase>({ kind: "starting" });
  const started = useRef(false);

  const start = useCallback(async () => {
    setPhase({ kind: "starting" });
    reset();

    try {
      const response = await fetch("/api/sessions", { method: "POST" });
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }
      setPhase({ kind: "waiting", session: (await response.json()) as Session });
    } catch (cause) {
      setPhase({ kind: "error", message: cause instanceof Error ? cause.message : String(cause) });
    }
  }, [reset]);

  // Once per mount, not once per effect run: the tab this lives in keeps its
  // children mounted but tears their effects down while hidden, and a session
  // minted on the way back would orphan the commands already copied out of here.
  useEffect(() => {
    if (started.current) {
      return;
    }

    started.current = true;
    void start();
  }, [start]);

  const token = phase.kind === "waiting" ? phase.session.token : null;

  useEffect(() => {
    if (!token) {
      return;
    }

    // 204 means nothing has been presented yet, so keep waiting. Cancelled on
    // unmount and whenever a new session replaces this one.
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;

    async function poll() {
      try {
        const response = await fetch(`/api/sessions/${token}`, { signal: controller.signal });

        if (response.status === 200) {
          const cesr = await response.text();
          setPhase({ kind: "delivered" });
          void verify(cesr);
          return;
        }

        // Only 204 means "nothing presented yet". Anything else is a server that
        // answers but cannot serve this session, and rescheduling would sit on
        // "waiting" forever with nothing to show for it.
        if (response.status !== 204) {
          setPhase({ kind: "error", message: `Server returned ${response.status}` });
          return;
        }
      } catch (cause) {
        if (controller.signal.aborted) {
          return;
        }
        // Stop rather than reschedule: the error UI offers "Try again", and a
        // hidden loop behind it would poll a dead server forever.
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
  }, [token, verify]);

  if (phase.kind === "error") {
    return (
      <Stack gap="md" mt="md">
        <Alert color="red">Could not reach the verifier: {phase.message}</Alert>
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

  if (phase.kind === "delivered") {
    return (
      <Stack gap="md" mt="md" align="flex-start">
        <Text>Credential presented. The result is below.</Text>
        <Button variant="default" onClick={() => void start()}>
          Present another
        </Button>
        <VerificationResult state={state} />
      </Stack>
    );
  }

  return (
    <Stack gap="md" mt="md">
      <Text>
        Run these where your credential lives. The first resolves this verifier so <code>kli</code> knows where to send;
        the second presents the credential.
      </Text>

      <CommandBlock>{commands(phase.session)}</CommandBlock>

      <Group gap="xs">
        <Loader size="sm" />
        <Text>Waiting for a presentation…</Text>
      </Group>

      <Group>
        <Button variant="default" onClick={() => void start()}>
          Start a new session
        </Button>
      </Group>
    </Stack>
  );
}
