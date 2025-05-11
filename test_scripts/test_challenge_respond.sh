#!/bin/bash
set -e

suffix=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 4)
random_name="test_$suffix"
name=${random_name}

kerijs() {
    # node --no-warnings ./dist/cli/main.js "$@"
    node --experimental-strip-types --no-warnings ./src/cli/main.ts "$@"
}

keripy() {
    kli "$@"
}

keripy init --name "$name" --nopasscode
keripy oobi resolve --name "$name" --oobi-alias wan --oobi "http://localhost:5642/oobi"
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
    --wits BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha \
    --wits BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM

keripy ends add \
    --name "$name" \
    --alias "$name" \
    --role mailbox \
    --eid BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kerijs resolve http://localhost:5642/oobi
kerijs resolve http://localhost:5643/oobi

kerijs_aid=$(kerijs incept --passcode foobar --wit BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha)
keripy_aid=$(keripy aid --name "$name" --alias "$name")

echo "KeriJS AID: $kerijs_aid"
echo "KeriPy AID: $keripy_aid"

keripy_oobi="http://localhost:5642/oobi/$keripy_aid"
kerijs_oobi="http://localhost:5642/oobi/$kerijs_aid"

kerijs resolve "$keripy_oobi"
keripy oobi resolve --name "$name" --oobi-alias kerijs --oobi "$kerijs_oobi"

words_json=$(keripy challenge generate --out json | jq '{ words: . }')
words_string=$(echo "$words_json" | jq -r '.words[]' | xargs)

kerijs send --sender "$kerijs_aid" --receiver "$keripy_aid" --topic "challenge" --route "/challenge/response" --data "$words_json"  --passcode foobar
keripy challenge verify --name "$name" --alias "$name" --words "$words_string" --signer kerijs
