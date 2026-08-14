import type { CheckStatus, CredentialCheckId } from "keri";

export const CHECK_LABELS: Record<CredentialCheckId, string> = {
  "acdc-said": "Credential SAID",
  "acdc-section-saids": "Section SAIDs",
  "issuer-kel": "Issuer key event log",
  "registry-inception": "Registry inception",
  "registry-anchor": "Registry anchored in issuer KEL",
  issuance: "Issuance event",
  "issuance-anchor": "Issuance anchored in issuer KEL",
  "revocation-anchor": "Revocation",
  edges: "Linked credentials",
  schema: "Schema",
};

export const STATUS_MARKS: Record<CheckStatus, string> = {
  passed: "✓",
  failed: "✗",
  skipped: "–",
  "not-applicable": "–",
  unchecked: "?",
};
