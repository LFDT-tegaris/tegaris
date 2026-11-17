# Licensing

Project code uses [Apache-2.0](../LICENSE). The Rust workspace and root Node.js package declare that license in their metadata.

The prose documentation listed in the [documentation index](../docs/README.md), together with the root community documents, uses [CC-BY-4.0](CC-BY-4.0.txt). Code examples use Apache-2.0. Files with a separate license notice retain their stated terms.

The CC-BY-4.0 text comes from [Creative Commons](https://creativecommons.org/licenses/by/4.0/legalcode.txt). When redistributing documentation, retain attribution, link the license and identify your changes as required by that license.

Third-party software and copied material retain their own copyright, license and notice requirements. A project's license declaration does not change the terms of its dependencies. Each release must include the notices required by the components it actually distributes; see the [release process](../RELEASE.md).

## Bundled font

The console includes the unmodified Manrope variable font used on [tegaris.io](https://tegaris.io). It is distributed under the SIL Open Font License 1.1; its [copyright and license notice](../apps/admin-web/public/brand/Manrope-LICENSE.txt) accompanies the font. These font terms apply separately from the code and documentation licenses.

## Collect dependency information

Use the pinned toolchain and install dependencies from the lockfile as described in
[local setup](../docs/getting-started.md). From the repository root, run:

```sh
pnpm run licenses
pnpm run sbom
```

Use the explicit `run` form: [pnpm built-in commands](https://pnpm.io/cli/run) take
precedence over same-named package scripts when `run` is omitted.

The commands use the repository's bounded runner. On a shared machine, reserve
memory for other running services using the options described in the
[testing guide](../docs/development/testing.md).

`pnpm run licenses` writes the resolved Node.js license inventory to
`artifacts/i01/licenses-pnpm.json` and Cargo package metadata to
`artifacts/i01/cargo-metadata.json`. Review the package versions, declared license
expressions and missing metadata. Cargo metadata identifies resolved packages; it
does not collect every package's license text or notice file. The outputs can
contain local filesystem paths, so review them before sharing. Generated inventory
files are ignored by Git.

`pnpm run sbom` writes `artifacts/i01/sbom-input-index.json`. This file records SHA-256
digests of the two dependency lockfiles, the root package manifest and the contract
manifest. It identifies inputs for later inventory work. It is not a release SBOM
and does not enumerate the components included in a binary or container image.

For a source-only release, review the exact tracked files, copied source and
assets, and include their required license and notice files. Dependency lockfiles
identify build inputs; they do not make downloaded dependencies part of the source
archive. Record any vendored dependencies as distributed source.

For official binaries or container images, generate the SPDX or CycloneDX SBOM
from the actual build and distribution contents. Account for bundled libraries,
base images, copied source, fonts and other assets as applicable. Collect their
required license and notice files and link the resulting inventory to the source
revision and artifact digest.
Keep contribution-rights and redistribution review separate from the automated
inventory: a declared license or successful command does not establish that those
reviews have been completed.

## Evaluate declared license expressions

The reusable evaluator in `scripts/evidence/license-policy.mjs` compares a declared
expression with a supplied policy. It does not contain an approved release policy
or provide legal clearance. Its regression tests run in the public unit-test job.

Policy lists distinguish allowed identifiers, identifiers requiring review and
identifiers whose qualification remains open. A declaration outside those lists
is denied. First-party packages receive the same checks as dependencies; missing
declarations and `UNLICENSED` metadata are denied.

The evaluator preserves parentheses and the [SPDX 2.3 operator
precedence](https://spdx.github.io/spdx-spec/v2.3.1/SPDX-license-expressions/).
An `AND` expression carries the most restrictive disposition of its operands;
an `OR` expression can use the least restrictive valid alternative. A `WITH`
exception is evaluated as a complete license-and-exception pair, which must be
listed explicitly in policy. Identifiers are matched without case sensitivity;
operators use uppercase. Malformed expressions and inputs exceeding the parser's
length or nesting limits are denied. This is policy evaluation, not validation
against the complete SPDX license registry.

Older Cargo dependencies can declare simple alternatives such as `MIT/Apache-2.0`.
An inventory caller may explicitly enable `legacySlash` to normalize a two-license
declaration to `OR`; ordinary expression evaluation rejects that spelling. This
compatibility handling does not approve a license or change dependency metadata.

Use the result to identify required review work. A technical pass may still include
review or unqualified findings; only an entirely allowed inventory is locally
eligible under the supplied policy. Neither result proves contribution rights,
notice completeness, license-text collection or permission to distribute a
particular artifact. The release owner must review those matters for the exact
release contents. An empty inventory fails the technical check; entries missing
package names or versions are rejected rather than counted as covered components.

## Node.js dependency SBOM

pnpm also provides a separate [built-in SBOM command](https://pnpm.io/cli/sbom).
To generate a CycloneDX inventory of production Node.js dependencies, run:

```sh
mkdir -p artifacts/dependencies
bash scripts/maintenance/run-bounded.sh --profile focused -- \
  pnpm sbom --sbom-format cyclonedx --prod \
  --out artifacts/dependencies/node.cdx.json
```

Account for other workloads when selecting the runner reservation. This inventory
covers the selected Node.js dependency graph. It does not include Rust crates,
container base images, operating-system packages or all files bundled into a
release. Review its root package, component versions and license metadata, and
retain the corresponding lockfile and source revision. Complete the artifact-level
inventory before treating it as the SBOM for a distributed application.

### Review optional platform components

A dependency-graph SBOM can include optional packages for platforms other than the
build machine. A Linux inventory may therefore list macOS or Windows variants of a
compiler or image-processing library. Some of those entries may have no license
metadata in the generated report because the corresponding package was not
installed. Confirm the cause for each entry; an empty license field is neither a
license grant nor proof that the component is absent from the distribution.

Reconcile the report with the actual release contents:

1. Identify the artifact's operating system, architecture and source revision.
2. Inspect the packaged dependency tree and bundled files, including native
   libraries. A package name or a successful build does not establish its presence
   or absence in the artifact.
3. For each included component, retain its version, origin, declared license and
   required license or notice files. Resolve missing metadata from the component's
   own distribution and license texts before publishing it.
4. Record excluded platform variants and the evidence for their exclusion in the
   artifact review. Preserve the original dependency-graph report separately so
   readers can distinguish dependency resolution from distribution contents.

Keep unresolved entries visible. Do not fill them with the project's Apache-2.0
license or drop them solely to produce a clean report. Source releases, Linux
images and packages for other platforms can have different distribution contents
and need inventories matching their respective scope.
