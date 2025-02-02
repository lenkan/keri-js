#!/bin/bash
set -e
salt="0ACDEyMzQ1Njc4OWxtbm9aBc"

kli init --name alice --salt "$salt" --nopasscode
kli oobi resolve --name alice --oobi-alias witness-1 --oobi "http://localhost:5641/oobi"
kli oobi resolve --name alice --oobi-alias witness-2 --oobi "http://localhost:5642/oobi"

kli incept \
    --name alice \
    --alias alice \
    --icount 1 \
    --isith "1" \
    --ncount 1 \
    --nsith 1 \
    --toad 1 \
    --transferable \
    --wits BNRSNuPrmgAeoossFZSejufyCaPLRRyEPRKn1wUxVeX9 \
    --wits BDOx8sbSqohKdpMFauzL4wTmzf2WwntKfsPov63-magB

kli status --name alice --alias alice

kli interact --name alice --alias alice --data '{"msg":"foobar"}'

kli export --name alice --alias alice > fixtures/alice.cesr
