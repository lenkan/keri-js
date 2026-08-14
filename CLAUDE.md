# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KERI-JS is a TypeScript implementation of KERI (Key Event Receipt Infrastructure), a cryptographic key management and identity framework. It is a pnpm workspace publishing two packages.

### Repository layout

```
packages/cesr/     "cesr"  — cesr/, encoding/
packages/keri/     "keri"  — core/, controller/, storage/, logging/,
                             sqlite-storage/, witness/, mailbox/, nodejs-utils/, cli/
apps/verifier/     private React app
test_consumer/     public-surface tests, run under Node and Deno
test_interop/      KERIpy compatibility tests
fixtures/          .cesr fixtures shared by both packages' tests
```

Each submodule has a `main.ts` that defines its public surface. Within a package, cross-submodule imports must target `../<submodule>/main.ts` — never reach into another submodule's internal files. Across packages, and from anything outside `packages/*/src`, use the package name (`cesr`, `cesr/encoding`, `keri`, `keri/witness`, …). Both rules are enforced by `scripts/check-imports.ts`, run as part of `pnpm run lint`.

Workspace members are declared in `pnpm-workspace.yaml`, and sibling dependencies use the `workspace:*` protocol so they can never resolve from the registry. `pnpm pack` rewrites `workspace:*` to the exact version being packed.

`keri` resolves `cesr` through its built `dist/`, so **the build must run before check, test or the app**. The `pretest`/`precheck` hooks do this automatically; `tsc -b` keeps it incremental.

## Commands

```sh
pnpm run build           # Build both packages to packages/*/dist
pnpm run test            # Unit tests (packages/*/src/**/*.test.ts)
pnpm run check           # TypeScript type-check (no emit)
pnpm run lint            # Biome lint + import boundary check
pnpm run format          # Biome formatting (write)

pnpm run test:consumer   # Public-surface tests through package names
pnpm run test:vector     # Cross-impl test vectors (packages/cesr/test_vectors/)
pnpm run test:interop    # Interop tests (requires .venv with KERIpy)

pnpm run dev:verifier                       # Watch-build the library alongside the Vite dev server
pnpm --filter @keri-js/verifier run check   # Type-check the app (needs a full `pnpm install`)
```

Tests use the native Node.js test runner. Unit test files live alongside source files.

Jobs that do not build the verifier app install with `pnpm install --frozen-lockfile --filter "!@keri-js/verifier"`, which keeps React and Vite out of the store and the virtual store entirely.

pnpm's isolated `node_modules` means an undeclared dependency fails rather than resolving through hoisting. Anything imported from `scripts/`, `test_interop/` or `test_consumer/` must be declared in the root `package.json`.

## TypeScript & Code Style

- `strict: true` enabled
- Build output goes to `packages/*/dist`
- Biome handles linting and formatting (`biome.json` at root)
- Cryptography uses `@noble/*` libraries exclusively
- `scripts/rewrite-declarations.ts` runs after `tsc -b`: `rewriteRelativeImportExtensions` leaves emitted declarations pointing at `.ts`, which TypeScript resolves but Deno does not

## Spec references

Curated, implementation-focused summaries of the protocols this codebase implements live under `docs/specs/`. Consult them before diving into upstream specs — they cover field labels, code tables, parsing logic, and cross-references to the source:

- [`docs/specs/cesr.md`](docs/specs/cesr.md) — CESR encoding, code tables, stream parsing (v1 + v2)
- [`docs/specs/keri.md`](docs/specs/keri.md) — KERI events, SAIDs, seals, witnesses (v1)
- [`docs/specs/acdc.md`](docs/specs/acdc.md) — ACDC body, schema/attribute/edge/rule sections, IPEX, TEL registries (v1)
- [`docs/kawa.md`](docs/kawa.md) — KAWA witness-agreement protocol detail

For anything not covered in the curated docs, fall back to the upstream specs linked at the top of each file.
