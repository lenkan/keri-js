import type { CredentialStatus, CredentialVerification } from "keri";
import { disclosedAttributes } from "keri";
import styles from "./CredentialResult.module.css";
import { CHECK_LABELS } from "./checks.ts";
import { cx } from "./components/class-names.ts";
import { Badge, Card, CheckItem, CheckList, Field, FieldList, type Tone } from "./components/main.ts";

const STATUS_TONES: Record<CredentialStatus, Tone> = {
  issued: "ok",
  revoked: "bad",
  unknown: "neutral",
};

function Claims({ result }: { result: CredentialVerification }) {
  const claims = disclosedAttributes(result.credential.body);
  if (claims.length === 0) {
    return null;
  }

  return (
    <FieldList>
      {claims.map(([key, value]) => (
        <Field key={key} label={key}>
          {typeof value === "object" ? JSON.stringify(value) : String(value)}
        </Field>
      ))}
    </FieldList>
  );
}

export function CredentialResult({ result }: { result: CredentialVerification }) {
  return (
    <Card>
      <header className={cx(styles.verdict, result.ok ? styles.ok : styles.bad)}>
        <strong>{result.ok ? "Verified" : "Not verified"}</strong>
        <Badge tone={STATUS_TONES[result.status]}>{result.status}</Badge>
      </header>

      <Claims result={result} />

      <FieldList mono>
        <Field label="Credential">{result.said}</Field>
        <Field label="Issuer">{result.issuer}</Field>
        {result.issuee && <Field label="Issued to">{result.issuee}</Field>}
        <Field label="Registry">{result.registry}</Field>
        <Field label="Schema">{result.schema}</Field>
        {result.issuedAt && <Field label="Issued">{result.issuedAt}</Field>}
        {result.revokedAt && <Field label="Revoked">{result.revokedAt}</Field>}
        {result.edges.map((edge) => (
          <Field key={edge.label} label={`↳ ${edge.label}`} tone={edge.ok ? "ok" : "bad"}>
            {edge.said}
          </Field>
        ))}
      </FieldList>

      <CheckList>
        {result.checks.map((check) => (
          <CheckItem key={check.id} state={check.status} label={CHECK_LABELS[check.id]} detail={check.detail} />
        ))}
      </CheckList>
    </Card>
  );
}
