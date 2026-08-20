import { Stack, Tabs, Text, Title } from "@mantine/core";
import { CommandBlock, Disclosure } from "./components/main.ts";
import { IdentityCard } from "./IdentityCard.tsx";
import type { Identity } from "./login/main.ts";
import { IpexMode, StreamMode } from "./modes/main.ts";

const TRY_IT_INSTALL_COMMANDS = "pip install keri==1.3.3";

const TRY_IT_SETUP_COMMANDS = `kli oobi resolve --name demo --oobi https://weboftrust.github.io/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao
kli vc registry incept --name demo --alias issuer --registry-name demo-registry`;

const TRY_IT_CREDENTIAL_COMMANDS = `kli vc create --name demo --alias issuer --registry-name demo-registry \\
  --schema EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao \\
  --recipient "$(kli aid --name demo --alias issuer)" \\
  --data '{"LEI":"1234567890123456789"}'
kli vc export --name demo --alias issuer \\
  --said "$(kli vc list --name demo --alias issuer --said --issued | tail -n 1)" \\
  --full > credential.cesr`;

/** Everything behind the login gate: who you are, and what you can do here. */
export function Portal({ identity, onLogout }: { identity: Identity; onLogout: () => void }) {
  return (
    <>
      <IdentityCard identity={identity} onLogout={onLogout} />

      <Title order={2} mt="xl">
        Verify a credential
      </Title>
      <Text c="dimmed" maw={640}>
        Bring an ACDC as a CESR stream, or have it presented to this session over IPEX — either way it is verified
        entirely in this page.
      </Text>

      <Disclosure summary="Don't have a credential handy? Issue one from your keystore">
        <Stack gap="md">
          <Text>
            With the same keystore you logged in with (needs <code>kli</code>, {TRY_IT_INSTALL_COMMANDS}), add a
            credential registry:
          </Text>

          <CommandBlock>{TRY_IT_SETUP_COMMANDS}</CommandBlock>

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
          <StreamMode />
        </Tabs.Panel>

        <Tabs.Panel value="ipex">
          <IpexMode />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
