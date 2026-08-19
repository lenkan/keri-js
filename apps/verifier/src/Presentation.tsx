import { Alert, Button, Group, Loader, Stack, Text } from "@mantine/core";
import { useCallback, useEffect, useState } from "react";
import { CommandBlock } from "./components/main.ts";

const API = import.meta.env.VITE_VERIFIER_API ?? "";
const POLL_MS = 2000;

interface Session {
  token: string;
  aid: string;
  oobi: string;
}

function commands({ token, aid, oobi }: Session): string {
  return `kli oobi resolve --name demo --oobi ${oobi} --oobi-alias verifier
kli ipex grant --name demo --alias issuer \\
  --said "$(kli vc list --name demo --alias issuer --said --issued | tail -n 1)" \\
  --recipient ${aid} \\
  --message ${token}`;
}

interface PresentationProps {
  onStream: (cesr: string) => void;
  /** Clears the last result, so a new session does not sit under the old one's verdict. */
  onReset: () => void;
}

export function Presentation({ onStream, onReset }: PresentationProps) {
  const [session, setSession] = useState<Session | null>(null);
  const [delivered, setDelivered] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const start = useCallback(async () => {
    setError(null);
    setSession(null);
    setDelivered(false);
    onReset();

    try {
      const response = await fetch(`${API}/api/sessions`, { method: "POST" });
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }
      setSession((await response.json()) as Session);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [onReset]);

  useEffect(() => {
    void start();
  }, [start]);

  useEffect(() => {
    if (!session) {
      return;
    }

    // 204 means nothing has been presented yet, so keep waiting. Cancelled on
    // unmount and whenever a new session replaces this one.
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;

    async function poll() {
      try {
        const response = await fetch(`${API}/api/sessions/${session?.token}`, { signal: controller.signal });

        if (response.status === 200) {
          const cesr = await response.text();
          setDelivered(true);
          onStream(cesr);
          return;
        }
      } catch (cause) {
        if (controller.signal.aborted) {
          return;
        }
        setError(cause instanceof Error ? cause.message : String(cause));
      }

      timer = setTimeout(poll, POLL_MS);
    }

    void poll();

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [session, onStream]);

  if (error) {
    return (
      <Stack gap="md" mt="md">
        <Alert color="red">Could not reach the verifier: {error}</Alert>
        <Group>
          <Button onClick={() => void start()}>Try again</Button>
        </Group>
      </Stack>
    );
  }

  if (!session) {
    return (
      <Group mt="md" gap="xs">
        <Loader size="sm" />
        <Text>Starting a session…</Text>
      </Group>
    );
  }

  if (delivered) {
    return (
      <Stack gap="md" mt="md" align="flex-start">
        <Text>Credential presented. The result is below.</Text>
        <Button variant="default" onClick={() => void start()}>
          Present another
        </Button>
      </Stack>
    );
  }

  return (
    <Stack gap="md" mt="md">
      <Text>
        Run these where your credential lives. The first resolves this verifier so <code>kli</code> knows where to send;
        the second presents the credential.
      </Text>

      <CommandBlock>{commands(session)}</CommandBlock>

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
