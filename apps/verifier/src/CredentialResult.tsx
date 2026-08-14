import type { CredentialVerification } from "keri";
import { disclosedAttributes } from "keri";
import { CHECK_LABELS, STATUS_MARKS } from "./checks.ts";

function Claims({ result }: { result: CredentialVerification }) {
  const claims = disclosedAttributes(result.credential.body);
  if (claims.length === 0) {
    return null;
  }

  return (
    <dl className="claims">
      {claims.map(([key, value]) => (
        <div key={key}>
          <dt>{key}</dt>
          <dd>{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CredentialResult({ result }: { result: CredentialVerification }) {
  return (
    <article className="result">
      <header className={`verdict verdict-${result.ok ? "ok" : "bad"}`}>
        <strong>{result.ok ? "Verified" : "Not verified"}</strong>
        <span className={`status status-${result.status}`}>{result.status}</span>
      </header>

      <Claims result={result} />

      <dl className="identifiers">
        <div>
          <dt>Credential</dt>
          <dd>{result.said}</dd>
        </div>
        <div>
          <dt>Issuer</dt>
          <dd>{result.issuer}</dd>
        </div>
        {result.issuee && (
          <div>
            <dt>Issued to</dt>
            <dd>{result.issuee}</dd>
          </div>
        )}
        <div>
          <dt>Registry</dt>
          <dd>{result.registry}</dd>
        </div>
        <div>
          <dt>Schema</dt>
          <dd>{result.schema}</dd>
        </div>
        {result.issuedAt && (
          <div>
            <dt>Issued</dt>
            <dd>{result.issuedAt}</dd>
          </div>
        )}
        {result.revokedAt && (
          <div>
            <dt>Revoked</dt>
            <dd>{result.revokedAt}</dd>
          </div>
        )}
        {result.edges.map((edge) => (
          <div key={edge.label}>
            <dt>{`↳ ${edge.label}`}</dt>
            <dd className={edge.ok ? "edge-ok" : "edge-bad"}>{edge.said}</dd>
          </div>
        ))}
      </dl>

      <ul className="checks">
        {result.checks.map((check) => (
          <li key={check.id} className={`check check-${check.status}`}>
            <span className="mark">{STATUS_MARKS[check.status]}</span>
            <span className="label">{CHECK_LABELS[check.id]}</span>
            {check.detail && <span className="detail">{check.detail}</span>}
          </li>
        ))}
      </ul>
    </article>
  );
}
