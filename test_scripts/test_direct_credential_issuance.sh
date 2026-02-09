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
keripy oobi resolve --name "$name" --oobi "https://weboftrust.github.io/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
keripy oobi resolve --name "$name" --oobi-alias wan --oobi "http://localhost:5642/oobi"

keripy incept \
    --name "$name" \
    --alias "$name" \
    --icount 1 \
    --isith "1" \
    --ncount 1 \
    --nsith 1 \
    --toad 1 \
    --transferable \
    --wits BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

keripy ends add \
    --name "$name" \
    --alias "$name" \
    --role mailbox \
    --eid BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kerijs_aid=$(kerijs incept --passcode foobar)
keripy_aid=$(keripy aid --name "$name" --alias "$name")

echo "KeriJS AID: $kerijs_aid"
echo "KeriPy AID: $keripy_aid"

keripy_oobi="http://localhost:5642/oobi/$keripy_aid"

kerijs resolve "$keripy_oobi"

registry_id=$(kerijs create-registry --passcode foobar --owner="$kerijs_aid")
echo "Created registry with ID: $registry_id"

rules='{
  "usageDisclaimer": {
    "l": "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled."
  },
  "issuanceDisclaimer": {
    "l": "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework."
  }
}'
data='{"LEI": "12312312312312321"}'

credential_id=$(kerijs create-credential --passcode foobar --registry "$registry_id" --receiver "$keripy_aid" --schema "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao" --data "$data" --rules "$rules")

kerijs ipex-grant --passcode foobar --said "$credential_id"

kli ipex list --name "$name" --type grant --poll

grant_said=$(kli ipex list --type grant --name "$name" --said | tail -n1)
kli ipex admit --name "$name" --alias "$name" --said "$grant_said" || true
kli vc list --name "$name" --alias "$name"
