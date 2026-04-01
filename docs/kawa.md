# KERI's Algorithm for Witness Agreement (KAWA)

## Purpose

A controller designates a pool of N **witnesses** to provide a highly available,
fault-tolerant service for its key event history (KERL). KAWA is the protocol
the controller runs to get each new event receipted by witnesses and to
cross-distribute those receipts so that every witness holds every other witness's
receipt in its KERL.

## Key Concepts

| Term     | Meaning                                                                           |
| -------- | --------------------------------------------------------------------------------- |
| N        | Total number of designated witnesses                                              |
| M (toad) | Threshold of accountable duplicity — minimum witnesses needed to confirm an event |
| F        | Maximum number of faulty (dishonest/unavailable) witnesses the system tolerates   |
| wig      | Witness indexed signature — a receipt couple re-encoded as an indexed sig         |
| KERL     | Key Event Receipt Log — the immutable, append-only log held by each witness       |

The controller declares N and M in the inception event (`b` and `toad` fields).
Subsequent rotations may change both. The constraint for immunity is **M > F**
and **F\* = N − M** (unavailable witnesses tolerated).

## Witnessing Policy

A witness signs (receipts) the **first verified version** of an event it sees and
ignores all later duplicates. This first-seen rule, combined with M > F, ensures
at most one valid agreement can exist for a given event sequence number.

## The Algorithm (Round-Robin)

The spec describes an efficient two-pass round-robin:

### Pass 1 — Collect receipts, forward prior ones

For each witness `w_i` in order:

1. Send the event **plus all receipts collected so far** (from `w_0 … w_{i-1}`).
2. Receive and store the receipt from `w_i`.

After this pass `w_i` holds receipts from `w_0 … w_{i-1}` but not from
`w_{i+1} … w_{N-1}`.

### Pass 2 — Fill the gaps

For each witness `w_i` in order:

1. Send only the receipts `w_i` has not yet seen (`w_{i+1} … w_{N-1}`).

Total: **at most 2 × N acknowledged exchanges** per event.

At the end, every witness has receipted the event and holds every other
witness's receipt, forming a complete KERL entry.

## Security Properties

- **Availability**: Any validator can obtain a proper KERL from any non-faulty
  witness on demand.
- **Byzantine fault tolerance**: Up to F dishonest witnesses cannot cause a
  second valid agreement to exist when M > F.
- **Dead exploit resistance**: Forging a prior KERL entry requires compromising
  both the controller keys _and_ at least M witnesses at that event — and
  existing copies held by watchers/jurors still enable duplicity detection.
- **Portability**: The witness set and threshold can be changed at rotation
  time, so trust is not locked to any particular witness infrastructure.

## Implementation in this Library

`src/core/kawa.ts` — `submitToWitnesses(event, endpoints)`

The event must already carry the controller's `ControllerIdxSigs` on its
attachments before being passed to this function.

```
Pass 1  for each endpoint:
          POST event → /receipts
          extract NonTransReceiptCouples → re-encode as indexed wig

Pass 2  for each endpoint:
          POST each other witness's rct message → mailbox
```

### Differences from the spec's round-robin

The implementation uses **two strict passes** rather than an interleaved
round-robin:

- Pass 1 only collects receipts (does not forward any during collection).
- Pass 2 sends all N−1 receipts individually to each witness, resulting in
  N×(N−1) mailbox messages instead of the spec's N additional exchanges.

For small witness sets (N = 2–5, typical in practice) the extra messages are
negligible. The end state is identical: every witness holds every other
witness's receipt.

### Toad (threshold M) not enforced

The current implementation requires **all N witnesses** to respond
successfully. If any witness is unreachable, `submitToWitnesses` throws.
The spec allows proceeding once M < N witnesses confirm; partial-fault
handling is not yet implemented.
