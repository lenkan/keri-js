import { Badge, Button, Card, Group, Text } from "@mantine/core";
import { Field, FieldList, TONE_COLORS } from "./components/main.ts";
import type { Identity } from "./login/main.ts";

export function IdentityCard({ identity, onLogout }: { identity: Identity; onLogout: () => void }) {
  return (
    <Card withBorder padding="lg" mt="xl">
      <Card.Section>
        <Group justify="space-between">
          <Text fw={700} c={TONE_COLORS.ok}>
            Logged in
          </Text>
          <Badge color={TONE_COLORS.ok} variant="light">
            authenticated
          </Badge>
        </Group>
      </Card.Section>

      <Card.Section>
        <FieldList>
          <Field mono label="Identifier">
            {identity.aid}
          </Field>
          <Field label="Sequence number">{identity.sequenceNumber}</Field>
          <Field label="Signing threshold">{[identity.signingThreshold].flat().join(", ")}</Field>
          {identity.signingKeys.map((key, index) => (
            <Field
              key={key}
              mono
              label={identity.signingKeys.length === 1 ? "Signing key" : `Signing key ${index + 1}`}
            >
              {key}
            </Field>
          ))}
          <Field mono label="Establishment">
            {identity.lastEstablishment.d}
          </Field>
          {identity.witnesses.length === 0 ? (
            <Field label="Witnesses">None — witness-less identifier</Field>
          ) : (
            identity.witnesses.map((witness, index) => (
              <Field key={witness} mono label={`Witness ${index + 1}`}>
                {witness}
              </Field>
            ))
          )}
          <Field label="Authenticated">{identity.authenticatedAt}</Field>
        </FieldList>
      </Card.Section>

      <Card.Section>
        <Group>
          <Button variant="default" onClick={onLogout}>
            Log out
          </Button>
        </Group>
      </Card.Section>
    </Card>
  );
}
