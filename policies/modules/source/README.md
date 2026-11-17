# Public module source baseline

This directory contains the versioned source inputs for the initial public module
contracts: 45 module definitions and the projected authority catalogue already
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

Public regeneration preserves the existing contract, manifest and historical
commitment bytes. Its separate `public-source-provenance.json` identifies the
public baseline used for the run. Preserving historical commitments does not
reverify the private historical source package, establish runtime implementation
coverage or approve a policy release.

Use the public commands above for this checkout. Commands embedded in generated
manifests record the original build process; they are preserved provenance, rather
than setup steps for public contributors.

## Change the baseline

The initial profile is immutable. A contract change needs a reviewed new baseline
version, its source inventory, compatible consumers and verification. Follow the
[proposal process](../../../docs/development/proposals.md); do not update expected
digests merely to suppress a generation failure.

Generation allows one writer per checkout. It stages complete outputs before
replacement and restores earlier files if a replacement fails. This is not a
crash-atomic filesystem transaction. If a process stops unexpectedly or rollback
fails, preserve `.openpc-module-generation.lock` and its backups. Establish whether
the writer is still running and reconcile the generated files before removing its
lock or trying another generation. Do not delete another writer's lock to continue.
