# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KERI-JS is a TypeScript implementation of KERI (Key Event Receipt Infrastructure), a cryptographic key management and identity framework. It is organized as an npm workspace monorepo with two packages:

- **`packages/cesr`** — Composable Event Streaming Representation: low-level encoding/decoding with zero runtime dependencies
- **`packages/keri`** — KERI core library: high-level key event and credential management, depends on `cesr`

## Commands

All commands can be run from the root or scoped to a workspace with `--workspace packages/keri` or `--workspace packages/cesr`.

```sh
npm run build           # Build all packages
npm run test            # Run all unit tests
npm run check           # TypeScript type-check (no emit)
npm run lint            # ESLint
npm run format          # Prettier formatting
npm run format:check    # Check formatting without writing

# Scoped examples
npm run test --workspace packages/keri
npm run test --workspace packages/cesr
npm run test:integration --workspace packages/keri  # requires running KERI witness
npm run test:interop --workspace packages/keri       # requires KERIpy demo running
npm run test:vector --workspace packages/cesr        # cross-impl test vectors
```

Tests use the native Node.js test runner (`--test`). There is no Jest/Vitest. Unit test files live alongside source files (`src/**/*.test.ts`).

## TypeScript & Code Style

- `strict: true` enabled workspace-wide
- Tests and source run directly via `--conditions=source` (no pre-compilation needed for tests)
- Build output goes to `dist/` in each package
- ESLint uses the modern flat config (`eslint.config.js` at root)
- Cryptography uses `@noble/*` libraries exclusively
