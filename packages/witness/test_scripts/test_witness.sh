#!/bin/bash
set -e

name="test_$(head /dev/urandom | tr -dc a-z0-9 | head -c 4)"

witness_url=${WITNESS_URL:-"http://localhost:3000"}
aid=$(curl -i "$witness_url/oobi" | grep -i 'Keri-Aid:' | cut -d' ' -f2 | tr -d '\r')

if [ -z "$aid" ]; then
    echo "Failed to get Keri-Aid from witness"
    exit 1
fi

kli init --name "$name" --nopasscode

kli oobi resolve --name "$name" \
    --oobi-alias test \
    --oobi "$witness_url/oobi/$aid"

kli incept --name "$name" \
    --alias test \
    --toad 1 \
    --wit "$aid" \
    --icount 1 \
    --ncount 1 \
    --isith 1 \
    --nsith 1 \
    --receipt-endpoint \
    --transferable

kli export --name "$name" --alias test
