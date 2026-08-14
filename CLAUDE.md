# CLAUDE.md

## Project Overview

KERI-JS is a TypeScript implementation of KERI (Key Event Receipt Infrastructure), a cryptographic key management and identity framework. It is a pnpm workspace publishing two packages.

Each submodule has a `main.ts` that defines its public surface. Within a package, cross-submodule imports must target `../<submodule>/main.ts` — never reach into another submodule's internal files. Across packages, and from anything outside `packages/*/src`, use the package name (`cesr`, `cesr/encoding`, `keri`, `keri/witness`, …). Both rules are enforced by `scripts/check-imports.ts`, run as part of `pnpm run lint`.

Workspace members are declared in `pnpm-workspace.yaml`, and sibling dependencies use the `workspace:*` protocol so they can never resolve from the registry. `pnpm pack` rewrites `workspace:*` to the exact version being packed.

`keri` resolves `cesr` through its built `dist/`, so **the build must run before check, test or the app**. The `pretest`/`precheck` hooks do this automatically; `tsc -b` keeps it incremental.

## Commands

```sh
pnpm --filter @keri-js/verifier run check   # Type-check the app (needs a full `pnpm install`)
```

pnpm's isolated `node_modules` means an undeclared dependency fails rather than resolving through hoisting. Anything imported from `scripts/`, `test_interop/` or `test_consumer/` must be declared in the root `package.json`.

## TypeScript & Code Style

- Cryptography uses `@noble/*` libraries exclusively
- Both packages publish `dist` **and** `src`, and their `exports` carry a `deno` condition pointing at the TypeScript source:

  ```json
  ".": {
    "deno": "./src/main.ts",
    "types": "./dist/main.d.ts",
    "default": "./dist/main.js"
  }
  ```

  Deno therefore reads the source and never touches the emitted output, which sidesteps the fact that `rewriteRelativeImportExtensions` leaves declarations pointing at `.ts` ([microsoft/TypeScript#61037](https://github.com/microsoft/TypeScript/issues/61037), open) and that Deno does not pick up a sibling `.d.ts` on its own. Node and bundlers fall through to `default` and get `dist`. Condition order matters: `deno` must come first.

## Spec references

Curated, implementation-focused summaries of the protocols this codebase implements live under `docs/specs/`. Consult them before diving into upstream specs — they cover field labels, code tables, parsing logic, and cross-references to the source:

- [`docs/specs/cesr.md`](docs/specs/cesr.md) — CESR encoding, code tables, stream parsing (v1 + v2)
- [`docs/specs/keri.md`](docs/specs/keri.md) — KERI events, SAIDs, seals, witnesses (v1)
- [`docs/specs/acdc.md`](docs/specs/acdc.md) — ACDC body, schema/attribute/edge/rule sections, IPEX, TEL registries (v1)
- [`docs/kawa.md`](docs/kawa.md) — KAWA witness-agreement protocol detail

For anything not covered in the curated docs, fall back to the upstream specs linked at the top of each file.
