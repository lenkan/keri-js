#!/bin/bash
set -e

suffix=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)
random_name="test_$suffix"
name=${random_name}

kerijs() {
    node --experimental-strip-types --no-warnings ./src/cli/main.ts "$@"
}

keripy() {
    kli "$@"
}

keripy init --name "$name" --nopasscode
keripy oobi resolve --name "$name" --oobi "https://dev-portal.vlei.dev/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
keripy oobi resolve --name "$name" --oobi "https://dev-portal.vlei.dev/oobi/ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
keripy oobi resolve --name "$name" --oobi "https://dev-portal.vlei.dev/oobi/EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"
keripy oobi resolve --name "$name" --oobi-alias wil --oobi "http://localhost:5643/oobi"

keripy incept \
    --name "$name" \
    --alias "$name" \
    --icount 1 \
    --isith "1" \
    --ncount 1 \
    --nsith 1 \
    --toad 1 \
    --transferable \
    --wits BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM

keripy ends add \
    --name "$name" \
    --alias "$name" \
    --role mailbox \
    --eid BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM

kerijs resolve http://localhost:5642/oobi

kerijs_aid=$(kerijs incept --passcode foobar --wit BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha)
keripy_aid=$(keripy aid --name "$name" --alias "$name")

echo "KeriJS AID: $kerijs_aid"
echo "KeriPy AID: $keripy_aid"

keripy_oobi="https://keria-ext.dev.idw-sandboxes.cf-deployments.org/oobi/EPOYJ1ZPuZcTgYqZDiOmaABT6XMs2BTtaimiInavSvQB/agent/EOK2uDQSpEquC09pfKmYpeyVTx17atl27ovHj6ZoKvGE"
keripy_oobi="http://localhost:5643/oobi/$keripy_aid"
kerijs_oobi="http://localhost:5642/oobi/$kerijs_aid/witness"

kerijs resolve "$keripy_oobi"
keripy oobi resolve --name "$name" --oobi-alias kerijs --oobi "$kerijs_oobi"

registry_id=$(kerijs create-registry --passcode foobar --owner="$kerijs_aid")
echo "Created registry with ID: $registry_id"

qvi_rules='{
  "usageDisclaimer": {
    "l": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled."
  },
  "issuanceDisclaimer": {
    "l": "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework."
  }
}'
qvi_data='{"LEI": "12312312312312321"}'
qvi_credential_id=$(kerijs create-credential --passcode foobar --registry "$registry_id" --receiver "$kerijs_aid" --schema "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao" --data "$qvi_data" --rules "$qvi_rules")


legal_entity_rules='{
  "usageDisclaimer": {
    "l": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled."
  },
  "issuanceDisclaimer": {
    "l": "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework."
  }
}'
legal_entity_data='{"LEI": "12312312312312321"}'
legal_entity_edges='{"qvi":{"n":"'$qvi_credential_id'","s":"EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"}}'
legal_entity_credential_id=$(kerijs create-credential --passcode foobar --registry "$registry_id" --receiver "$kerijs_aid" --schema "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY" --data "$legal_entity_data" --rules "$legal_entity_rules" --edges "$legal_entity_edges")

ecr_rules='{
  "usageDisclaimer": {
    "l": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled."
  },
  "issuanceDisclaimer": {
    "l": "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework."
  },
  "privacyDisclaimer": {
    "l": "It is the sole responsibility of Holders as Issuees of an ECR vLEI Credential to present that Credential in a privacy-preserving manner using the mechanisms provided in the Issuance and Presentation Exchange (IPEX) protocol specification and the Authentic Chained Data Container (ACDC) specification. https://github.com/WebOfTrust/IETF-IPEX and https://github.com/trustoverip/tswg-acdc-specification."
  }
}'

ecr_data='{"LEI": "12312312312312321","personLegalName":"John Doe","engagementContextRole":"Test Driver"}'
ecr_edges='{"le":{"n":"'$legal_entity_credential_id'","s":"ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"}}'
ecr_salt="0ACnKiVvJ-_R-C36cQhpIgTw"
ecr_credential_id=$(kerijs create-credential --passcode foobar --registry "$registry_id" --receiver "$keripy_aid" --schema "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw" --data "$ecr_data" --rules "$ecr_rules" --edges "$ecr_edges" --salt "$ecr_salt")

echo "Created credential with id: $qvi_credential_id"
echo "Created credential with id: $legal_entity_credential_id"
echo "Created credential with id: $ecr_credential_id"

kerijs ipex-grant --passcode foobar --said "$ecr_credential_id"

keripy query --name "$name" --alias "$name" --prefix "$kerijs_aid"
kli ipex list --name "$name" --type grant --poll

grant_said=$(kli ipex list --type grant --name "$name" --said | tail -n1)

if [ -z "$grant_said" ]; then
    echo "Grant not found"
    exit 1
fi

kli ipex admit --name "$name" --alias "$name" --said "$grant_said" || true
kli vc list --name "$name" --alias "$name"
