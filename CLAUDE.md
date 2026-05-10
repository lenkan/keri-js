# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KERI-JS is a TypeScript implementation of KERI (Key Event Receipt Infrastructure), a cryptographic key management and identity framework. It is a single npm package with multiple export entry points.

### Source layout (`src/`)

- **`cesr/`** — Composable Event Streaming Representation: low-level encoding/decoding primitives
- **`core/`** — KERI core logic: key events, credentials, signing, verification
- **`controller/`** — Identifier controller
- **`encoding/`** — Base64 and UTF-8 encoding utilities
- **`storage/`** — Storage backends (e.g. SQLite)
- **`witness/`** — Witness node implementation

Each submodule has a `main.ts` that defines its public surface. Cross-submodule imports must target `../<submodule>/main.ts` — never reach into another submodule's internal files. Enforced by `scripts/check-imports.ts`, run as part of `npm run lint`.

## Commands

```sh
npm run build           # Compile TypeScript to dist/
npm run test            # Run all unit tests (src/**/*.test.ts)
npm run check           # TypeScript type-check (no emit)
npm run lint            # Biome lint
npm run format          # Biome formatting (write)

npm run test:interop      # Interop tests (requires KERIpy demo running)
npm run test:vector       # Cross-impl test vectors (test_vectors/)
```

Tests use the native Node.js test runner. Unit test files live alongside source files (`src/**/*.test.ts`).

## TypeScript & Code Style

- `strict: true` enabled
- Build output goes to `dist/`
- Biome handles linting and formatting (`biome.json` at root)
- Cryptography uses `@noble/*` libraries exclusively

## Spec references

Curated, implementation-focused summaries of the protocols this codebase implements live under `docs/specs/`. Consult them before diving into upstream specs — they cover field labels, code tables, parsing logic, and cross-references to `src/`:

- [`docs/specs/cesr.md`](docs/specs/cesr.md) — CESR encoding, code tables, stream parsing (v1 + v2)
- [`docs/specs/keri.md`](docs/specs/keri.md) — KERI events, SAIDs, seals, witnesses (v1)
- [`docs/specs/acdc.md`](docs/specs/acdc.md) — ACDC body, schema/attribute/edge/rule sections, IPEX, TEL registries (v1)
- [`docs/kawa.md`](docs/kawa.md) — KAWA witness-agreement protocol detail

For anything not covered in the curated docs, fall back to the upstream specs linked at the top of each file.
