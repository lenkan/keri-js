#!/bin/bash
set -e
salt="0ACDEyMzQ1Njc4OWxtbm9aBc"
# rm -rf /usr/local/var/keri
# rm -rf "$HOME/.keri"

kli init --name alice --salt "$salt" --nopasscode --config-dir config --config-file demo-witness-oobis

sleep 2

kli incept --name alice --alias alice --icount 1 --isith "1" --ncount 1 --nsith 1 --toad 1 --transferable --wits BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM
kli status --name alice --alias alice

kli interact --name alice --alias alice --data '{"msg":"foobar"}'

kli export --name alice --alias alice > fixtures/alice.json
