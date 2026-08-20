import { Container, Text, Title } from "@mantine/core";
import { LoginWizard, useLogin } from "./login/main.ts";
import { Portal } from "./Portal.tsx";

export function App() {
  const login = useLogin();

  return (
    <Container size="md" py="xl">
      <Title order={1}>KERI Portal</Title>

      {login.phase.kind === "authenticated" ? (
        <Portal identity={login.phase.identity} onLogout={login.restart} />
      ) : (
        <>
          <Text c="dimmed" maw={640}>
            Prove who you are to enter — no password, no email. Your KERI identifier is the account, your keystore holds
            the keys, and this portal only ever sees your public key event log and a signed challenge.
          </Text>

          <LoginWizard {...login} />

          <Text size="sm" c="dimmed" mt="xl" maw={640}>
            Inside: your live key state, and ACDC credential verification over IPEX. Rotate your keys and log in again —
            it still works, because the portal verifies against your key event log, not a stored password.
          </Text>
        </>
      )}
    </Container>
  );
}
