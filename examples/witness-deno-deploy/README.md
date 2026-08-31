# KERI witness on Deno Deploy

One file. Deno KV backs the `Store`, `Deno.serve` takes the witness's `fetch`, and there is no build
step — the `deno` export condition points at the TypeScript source.

Deno Deploy runs isolates in several regions at once, so there is no single writer. That is what
`Store.create` is for: mailbox ordinals are allocated by reading the tail and writing one past it,
which two simultaneous deposits would both resolve to the same slot. The KV adapter claims the slot
with an atomic `check({ versionstamp: null })` and moves up when it loses.

## Run it

```sh
WITNESS_SEED=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=') \
WITNESS_URL=http://localhost:8000 \
deno task dev
```

It prints the witness AID. Point a controller at it:

```sh
kli oobi resolve --name ctrl --oobi-alias wit --oobi http://localhost:8000/oobi/<witness-aid>
kli incept --name ctrl --alias ctrl --wits <witness-aid> --toad 1 --receipt-endpoint \
  --icount 1 --isith 1 --ncount 1 --nsith 1 --transferable
```

## Deploy it

Set `WITNESS_SEED` and `WITNESS_URL` in the project's environment, then `deno deploy`.

`WITNESS_SEED` is the witness: the AID is the public key derived from it, so losing it leaves every
controller that lists it as a backer stuck below its threshold. `WITNESS_URL` is signed into those
controllers' KELs through `/loc/scheme`, so it has to stay reachable for as long as they do.

## Copying this out

`deno.json` maps `keri/witness` to this repository's source. Point it at `npm:keri/witness` instead.
