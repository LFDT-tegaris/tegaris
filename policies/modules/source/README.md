# Public module source baseline

This directory contains the versioned source inputs for public module baseline version 2:
45 module definitions and the projected authority catalogue already
included in the contribution. It contains no environment credentials or runtime
permission grants.

`baseline.json` records the input inventory and the expected contract outputs.
The source loader also pins that manifest's digest independently in code. Editing
an input and its declared digest together cannot make an altered source package
valid under this profile.

## Regenerate the contracts

Use the pinned toolchain and locked dependencies from the
[development guide](../../../docs/development/README.md). From the repository root:

```sh
pnpm --filter @openpc/module-registry run generate:public
pnpm --filter @openpc/module-registry run generate:public:check
```

The repository-wide `pnpm run generate` command selects this public path for the
module registry. Check mode reads the source and generated files without replacing
them. It rejects missing outputs, changed inputs and output drift.

The current scripts select `public-v2`. To reproduce `public-v1`, use the earlier
checkout containing that baseline; do not mix its outputs with this revision.

Public baseline version 2 preserves the module definitions, manifests and generated
TypeScript and Rust contracts. It revises fourteen planning statements into
project-facing requirements and regenerates the associated trace fingerprints and
negative test inputs. Requirement identifiers, dispositions, relationships,
negative-behavior rules and expected permission outcomes are preserved.

`public-source-provenance.json` identifies the baseline used for the run. Historical
record hashes remain provenance references to the original records; they do not
claim that revised wording is byte-identical to those records. The historical
generation profile and its authentication checks remain separate. Neither source
profile establishes runtime implementation coverage or approves a policy release.

Use the public commands above for this checkout. Commands embedded in generated
manifests record the original build process; they are preserved provenance, rather
than setup steps for public contributors.

## Change the baseline

Each published baseline is immutable. A contract change needs a reviewed new baseline
version, its source inventory, compatible consumers and verification. Follow the
[proposal process](../../../docs/development/proposals.md); do not update expected
digests merely to suppress a generation failure.

Generation allows one writer per checkout. It stages complete outputs before
replacement and restores earlier files if a replacement fails. This is not a
crash-atomic filesystem transaction. If a process stops unexpectedly or rollback
fails, preserve `.openpc-module-generation.lock` and its backups. Establish whether
the writer is still running and reconcile the generated files before removing its
lock or trying another generation. Do not delete another writer's lock to continue.
