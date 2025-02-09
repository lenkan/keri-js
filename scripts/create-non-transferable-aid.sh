#!/bin/bash
rm -rf ~/.keri
name="witness"

kli init --nopasscode --name "$name" --salt "$SALT"

kli incept \
    --name "$name" \
    --alias "$name" \
    --ncount 1 \
    --icount 1 \
    --isith 1 \
    --nsith 1 \
    --toad 0

kli export --name "$name" --alias "$name"

