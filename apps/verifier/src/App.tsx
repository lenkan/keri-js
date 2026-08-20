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
            Log in by proving control of a KERI identifier: supply your key event log, then sign a challenge with your
            current keys. Once in, you can inspect your key state and verify ACDC credentials.
          </Text>

          <LoginWizard {...login} />
        </>
      )}
    </Container>
  );
}
