# Module contracts

The checked-in module contracts describe the registry, installation dependencies,
policy interfaces and conformance cases used by Tegaris. Start with
[`module-registry.json`](generated/module-registry.json) to find a module and its
manifest. The registry contains 33 modules and their deterministic installation
order; dependencies must remain acyclic.

## Find the contract you need

| File                                           | Purpose                                                                         |
| ---------------------------------------------- | ------------------------------------------------------------------------------- |
| `generated/manifests/`                         | A manifest for each module, including its identity, interfaces and dependencies |
| `generated/module-registry.json`               | Registry entries, manifest digests, dependency edges and installation order     |
| `generated/module-manifest.schema.json`        | Canonical manifest schema                                                       |
| `generated/module-manifest.compat.schema.json` | Schema projection used by the current validator                                 |
| `generated/module-contract-catalog.json`       | Shared types, states, operations, errors, events and configuration              |
| `generated/module-traceability.jsonl`          | Links between module requirements and verification obligations                  |
| `generated/module-conformance-fixtures.json`   | Positive cases and negative profiles for contract verification                  |
| `generated/generated-source-index.json`        | File commitments checked against the included snapshot                          |

A matching manifest digest establishes the expected contract bytes. It does not
establish that a deployed service implements every obligation or that a policy
has been approved and activated.

For deployment preparation and the human registration/install/activation sequence,
read the [module operations guide](../../docs/operations/modules.md). It separates
the checked-in contract snapshot from a signed release and current enabled bindings.

## Verify the checked-in snapshot

From the repository root, install the locked dependencies using the
[development setup guide](../../docs/getting-started.md), then run:

```sh
bash scripts/maintenance/run-bounded.sh --profile focused -- \
  pnpm exec vitest run --maxWorkers=2 \
  --config tests/conformance/modules/portable.vitest.config.ts
```

The focused profile assumes its reservation covers the machine's other work.
Account for retained containers as described in the
[testing guide](../../docs/development/testing.md).

These tests use files included in the checkout. They check file commitments,
manifest validation, registry digests, installation ordering and the expected
catalogue and conformance contents. They do not start a runtime or replace the
native policy evaluator and integration tests.

## Regenerate from public source

The [public source baseline](source/README.md) contains the versioned module
definitions and projected authority catalogue. To regenerate and verify the initial
public snapshot, run these commands from the repository root:

```sh
pnpm --filter @openpc/module-registry run generate:public
pnpm --filter @openpc/module-registry run generate:public:check
```

The public profile verifies its complete input inventory and preserves the current
contract bytes. Its provenance records public-source verification separately from
historical source commitments. It grants no runtime permissions and does not
replace the portable contract tests or integration qualification.

## Propose a contract change

Treat the generated files as one versioned snapshot. Do not fix a digest mismatch
by changing only the expected hash, and do not hand-edit a generated manifest as
the sole implementation of a behavior change.

1. Identify the owning module and the actors, resources and policy decisions affected.
2. Describe compatibility for existing manifests, stored policies, clients and retained data.
3. Include the schema, implementation and consumer changes needed for the new behavior.
4. Add verification for permitted inputs, typed denials and incompatible or malformed inputs.
5. Ask maintainers to review the complete generated snapshot and its provenance before merging a replacement.

For a material change, use the [proposal process](../../docs/development/proposals.md).
Record the resulting behavior and migration requirements in the developer and
operator documentation. Existing signed inputs and applied migrations must remain
verifiable after the change.
