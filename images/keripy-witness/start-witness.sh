#!/bin/bash
set -e

port=${HTTP_PORT:-"5631"}
tcp=${TCP_PORT:-"5632"}
hostname=${PUBLIC_HOSTNAME:-"localhost"}
protocol=${PUBLIC_PROTOCOL:-"http"}
url="$protocol://$hostname:$port"
salt=${SALT:-"0ACDEyMzQ1Njc4OWxtbm9aBc"}
name=${NAME:-"witness"}
base=${BASE:-"witness"}
location=${LOCATION:-"$url"}
log_level=${LOG_LEVEL:-"CRITICAL"}

kli init \
    --salt "$salt" \
    --name "$name" \
    --base "$base" \
    --nopasscode \
    --config-file "$name"

status() {
    kli status --name "$name" --alias "$name" --base "$base"
}

incept() {
    kli incept \
        --name "$name" \
        --alias "$name" \
        --base "$base" \
        --ncount 1 \
        --icount 1 \
        --isith 1 \
        --nsith 1 \
        --toad 0

    prefix=$(status | grep "^Identifier: " | cut -d ' ' -f 2)

    kli ends add \
        --name "$name" \
        --alias "$name" \
        --base "$base" \
        --role controller \
        --eid "$prefix"

    kli location add \
        --name "$name" \
        --alias "$name" \
        --base "$base" \
        --url "$location"
}

status || incept 

kli witness start \
    --name "$name" \
    --alias "$name" \
    --base "$base" \
    --loglevel "$log_level" \
    -H "$port" \
    -T "$tcp"
