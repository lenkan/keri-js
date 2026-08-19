import { Container, Stack, Tabs, Text, Title } from "@mantine/core";
import { CommandBlock, Disclosure } from "./components/main.ts";
import { IpexMode, StreamMode } from "./modes/main.ts";

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

export function App() {
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
          <StreamMode />
        </Tabs.Panel>

        <Tabs.Panel value="ipex">
          <IpexMode />
        </Tabs.Panel>
      </Tabs>
    </Container>
  );
}
