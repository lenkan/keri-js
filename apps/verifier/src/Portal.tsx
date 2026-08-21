import { Stack, Text, Title } from "@mantine/core";
import { CommandBlock, Disclosure } from "./components/main.ts";
import { IdentityCard } from "./IdentityCard.tsx";
import type { Identity } from "./login/main.ts";
import { PresentMode } from "./modes/main.ts";

const TRY_IT_INSTALL_COMMANDS = "pip install keri==1.3.6";

const TRY_IT_SETUP_COMMANDS = `kli oobi resolve --name demo --oobi https://weboftrust.github.io/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli vc registry incept --name demo --alias issuer --registry-name demo-registry`;

const TRY_IT_CREDENTIAL_COMMANDS = `kli vc create --name demo --alias issuer --registry-name demo-registry \\
  --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao \\
  --recipient "$(kli aid --name demo --alias issuer)" \\
  --data '{"LEI":"1234567890123456789"}'`;

export function Portal({ identity, onLogout }: { identity: Identity; onLogout: () => void }) {
  return (
    <>
      <IdentityCard identity={identity} onLogout={onLogout} />

      <Title order={2} mt="xl">
        Present a credential
      </Title>
      <Text c="dimmed" maw={640}>
        Present an ACDC issued to your identifier over IPEX. Verification runs entirely in this page, including that the
        credential names you as its issuee.
      </Text>

      <Disclosure summary="Don't have a credential yet? Issue one to yourself">
        <Stack gap="md">
          <Text>
            With the same keystore you logged in with (needs <code>kli</code>, {TRY_IT_INSTALL_COMMANDS}), add a
            credential registry:
          </Text>

          <CommandBlock>{TRY_IT_SETUP_COMMANDS}</CommandBlock>

          <Text>Issue a credential to your own identifier — repeat to create more:</Text>

          <CommandBlock>{TRY_IT_CREDENTIAL_COMMANDS}</CommandBlock>

          <Text>Then present it with the command below.</Text>
        </Stack>
      </Disclosure>

      <PresentMode identity={identity} />
    </>
  );
}
