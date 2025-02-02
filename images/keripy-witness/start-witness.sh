#!/bin/bash
set -e

port=${HTTP_PORT:-"5631"}
hostname=${PUBLIC_HOSTNAME:-"localhost"}
protocol=${PUBLIC_PROTOCOL:-"http"}
url="$protocol://$hostname:$port"
salt=${SALT:-"0ACDEyMzQ1Njc4OWxtbm9aBc"}
name=${NAME:-"witness"}

kli init \
    --salt "$salt" \
    --name "$name" \
    --nopasscode \
    --config-file "$name"

status() {
    kli status --name "$name" --alias "$name"
}

incept() {
    kli incept \
        --name "$name" \
        --alias "$name" \
        --ncount 1 \
        --icount 1 \
        --isith 1 \
        --nsith 1 \
        --toad 0

    prefix=$(status | grep "^Identifier: " | cut -d ' ' -f 2)

    kli ends add \
        --name "$name" \
        --alias "$name" \
        --role controller \
        --eid "$prefix"

    kli location add \
        --name "$name" \
        --alias "$name" \
        --url "$url"
}

status || incept 

kli witness start \
    --name "$name" \
    --alias "$name" \
    -H "$port"
