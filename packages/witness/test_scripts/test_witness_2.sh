#!/bin/bash
set -e

name="test_$(head /dev/urandom | tr -dc a-z0-9 | head -c 4)"

witness_1_url="http://localhost:3001"
witness_2_url="http://localhost:3002"
aid_1=$(curl -i "$witness_1_url/oobi" | grep -i 'Keri-Aid:' | cut -d' ' -f2 | tr -d '\r')
aid_2=$(curl -i "$witness_2_url/oobi" | grep -i 'Keri-Aid:' | cut -d' ' -f2 | tr -d '\r')

if [ -z "$aid_1" ]; then
    echo "Failed to get Keri-Aid from witness 1"
    exit 1
fi

if [ -z "$aid_2" ]; then
    echo "Failed to get Keri-Aid from witness 2"
    exit 1
fi

kli init --name "$name" --nopasscode

kli oobi resolve --name "$name" \
    --oobi-alias test \
    --oobi "$witness_1_url/oobi/$aid_1"

kli oobi resolve --name "$name" \
    --oobi-alias test \
    --oobi "$witness_2_url/oobi/$aid_2"

kli incept --name "$name" \
    --alias test \
    --toad 2 \
    --wit "$aid_1" \
    --wit "$aid_2" \
    --icount 1 \
    --ncount 1 \
    --isith 1 \
    --nsith 1 \
    --receipt-endpoint \
    --transferable

kli export --name "$name" --alias test
