import { Badge, Card, Group, Text } from "@mantine/core";
import type { CredentialStatus, CredentialVerification } from "keri";
import { disclosedAttributes } from "keri";
import { CHECK_LABELS } from "./checks.ts";
import { CheckItem, CheckList, Field, FieldList, TONE_COLORS, type Tone } from "./components/main.ts";

const STATUS_TONES: Record<CredentialStatus, Tone> = {
  issued: "ok",
  revoked: "bad",
  unknown: "neutral",
};

export function CredentialResult({ result }: { result: CredentialVerification }) {
  const claims = disclosedAttributes(result.credential.body);

  return (
    <Card withBorder padding="lg" mt="xl">
      <Card.Section>
        <Group justify="space-between">
          <Text fw={700} c={TONE_COLORS[result.ok ? "ok" : "bad"]}>
            {result.ok ? "Verified" : "Not verified"}
          </Text>
          <Badge color={TONE_COLORS[STATUS_TONES[result.status]]} variant="light">
            {result.status}
          </Badge>
        </Group>
      </Card.Section>

      {claims.length > 0 && (
        <Card.Section>
          <FieldList>
            {claims.map(([key, value]) => (
              <Field key={key} label={key}>
                {typeof value === "object" ? JSON.stringify(value) : String(value)}
              </Field>
            ))}
          </FieldList>
        </Card.Section>
      )}

      <Card.Section>
        <FieldList>
          <Field mono label="Credential">
            {result.said}
          </Field>
          <Field mono label="Issuer">
            {result.issuer}
          </Field>
          {result.issuee && (
            <Field mono label="Issued to">
              {result.issuee}
            </Field>
          )}
          <Field mono label="Registry">
            {result.registry}
          </Field>
          <Field mono label="Schema">
            {result.schema}
          </Field>
          {result.issuedAt && (
            <Field mono label="Issued">
              {result.issuedAt}
            </Field>
          )}
          {result.revokedAt && (
            <Field mono label="Revoked">
              {result.revokedAt}
            </Field>
          )}
          {result.edges.map((edge) => (
            <Field key={edge.label} mono label={`↳ ${edge.label}`} tone={edge.ok ? "ok" : "bad"}>
              {edge.said}
            </Field>
          ))}
        </FieldList>
      </Card.Section>

      <Card.Section>
        <CheckList>
          {result.checks.map((check) => (
            <CheckItem key={check.id} state={check.status} label={CHECK_LABELS[check.id]} detail={check.detail} />
          ))}
        </CheckList>
      </Card.Section>
    </Card>
  );
}
