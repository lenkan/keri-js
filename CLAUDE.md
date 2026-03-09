# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

A JavaScript/TypeScript playground library implementing [KERI (Key Event Receipt Infrastructure)](docs/KERI.md) — a cryptographic identity protocol based on verifiable key event logs. The library can create and verify KERI events and ACDC credentials compatible with KERIpy.

## Commands

```bash
npm test                    # run unit tests (src/**/*.test.ts)
npm run test:integration    # run integration tests against live KERIpy (requires .venv)
npm run build               # compile TypeScript to dist/
npm run check               # typecheck without emitting
npm run lint                # ESLint
npm run format              # Prettier format
npm run format:check        # check formatting
```

To run a single test by name pattern:

```bash
node --test --no-warnings --test-name-pattern 'pattern' 'src/**/*.test.ts'
```

## Architecture

The codebase is organized into four main layers:

### 1. Core layer (`src/core/`)

Pure KERI protocol logic with no external dependencies beyond cryptographic primitives and CESR.

- **`key-event.ts`** — Inception, interaction, and rotation event types and builders
- **`key-event-log.ts`** — `KeyEventLog` class: immutable Key Event Log state machine. Accumulates events via `append()` (verifying signatures) and tracks the current `KeyState` (signing keys, thresholds, backers, etc.)
- **`registry-event.ts`** — ACDC registry events (`vcp`, `iss`, `rev`)
- **`routed-event.ts`** — Routed events (`exn`, `qry`, `rpy`)
- **`receipt-event.ts`** — Receipt events (`rct`)
- **`credential.ts`** — ACDC credential type and builder
- **`verify.ts`** — Threshold signature verification supporting integer and weighted fractional thresholds (`"1/2"` style strings)
- **`sign.ts`** — Signing helpers
- **`keys.ts`** — Key pair generation
- **`said.ts`** — SAID (Self-Addressing IDentifier) computation via Blake3
- **`events.ts`** — Shared utilities: `encodeEvent`, `formatDate`, `randomNonce`
- **`threshold.ts`** — Threshold parsing and evaluation
- **`main.ts`** — Core public API entry point; exports the `keri` object with event builders

### 2. Keystore layer (`src/keystore/`)

- **`key-manager.ts`** — `PassphraseKeyManager`: manages Ed25519 keys encrypted at rest. Keys are stored by their CESR-encoded public key; digests (Blake3 of public key) map to public keys for pre-commitment lookup.
- **`encrypt.ts`** — Passphrase-based AES encryption for key storage.

### 3. DB layer (`src/db/`)

- **`storage.ts`** — Storage abstractions
- **`db.ts`** — SQLite-backed repositories (events, registries, credentials, keys, contacts, replies)
- **`*-repository.ts`** — Typed repository implementations

### 4. Controller layer (`src/controller/`)

- **`controller.ts`** — `Controller`: high-level orchestrator. Handles the full lifecycle: `incept → rotate → anchor → createRegistry → createCredential → issueCredential → grant`. Coordinates signing, witness submission, mailbox forwarding, and SQLite persistence.
- **`witness-client.ts`** — HTTP client for submitting events to KERIpy witnesses (`POST /receipts`).
- **`mailbox-client.ts`** — HTTP client for the KERI mailbox protocol.
- **`contact-manager.ts`** — Manages contacts.

### Public API

`src/main.ts` is the library entry point (also mapped as the `#keri` import alias in `package.json`). The CLI lives in `src/cli/main.ts`.

## Key dependencies

- **`cesr`** — CESR encoding/decoding. Provides `Message` (body + `Attachments`), `Matter` (base CESR primitive), `Indexer` (indexed signatures), `VersionString`, and `parse()`. Most KERI wire-format work goes through this package.
- **`@noble/curves`**, **`@noble/ed25519`**, **`@noble/hashes`** — cryptographic primitives (Ed25519 signing, Blake3 hashing).

## TypeScript conventions

- Module format: ESM (`"type": "module"`), `"module": "nodenext"` resolution.
- Import paths use `.ts` extensions — `rewriteRelativeImportExtensions` rewrites them to `.js` on build.
- `erasableSyntaxOnly: true` — no TypeScript enums or other non-erasable syntax.
- `verbatimModuleSyntax: true` — use `import type` for type-only imports.
- The internal alias `#keri` resolves to `./src/main.ts` (configured in `package.json` `imports`).
- The internal alias `#keri/core` resolves to `./src/core/main.ts`.
- **Import rule**: Code outside `src/core/` must import from `src/core/` using the `#keri/core` alias (e.g. `import { KeyEventLog } from '#keri/core'`), never via relative paths. This keeps the core layer extractable as a standalone library.

## Integration tests

Integration tests in `test_integration/` require a running KERIpy witness. The Python environment is managed in `.venv/` using the packages listed in `requirements.txt`.
