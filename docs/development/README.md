# Development

Develop from the selected repository revision with its pinned toolchain and lockfiles. Begin with [local setup](../getting-started.md), then use this guide to identify the owner of your change and its verification scope.

## Repository layout

| Path                              | Responsibility                                  | Typical change                                               |
| --------------------------------- | ----------------------------------------------- | ------------------------------------------------------------ |
| `apps/admin-web`                  | Console and BFF integration                     | Forms, directories, session-aware workflows and presentation |
| `services`                        | TypeScript services and Rust runtime components | Authoritative behavior, persistence and request handling     |
| `crates`                          | Shared Rust libraries                           | Domain types, validation and runtime policy logic            |
| `packages`                        | Shared TypeScript libraries                     | Contracts, security primitives and UI support                |
| `schemas`, `proto`                | Public/service contracts                        | Interface definitions and validation requirements            |
| `generated`                       | Generated projections                           | Outputs updated through the owning generators                |
| `migrations`                      | Database changes                                | New migrations through the owning subsystem                  |
| `tests`                           | Behavioral and operational verification         | Allowed/denied, integration, browser and recovery cases      |
| `deploy`, `containers`, `scripts` | Packaging and operations                        | Reproducible builds, setup and supported lifecycle commands  |

## Work on one behavior

Write down the actor, context, input, expected result and forbidden effect. Locate the owning service before changing its callers. A console-only workaround cannot fix an authorization defect in a backend owner.

For an isolated correction, use focused tests first. For a cross-service change, identify every affected consumer, persistence boundary and recovery path. Keep the original failure as a regression case.

Do not mix unrelated refactoring into a behavior change. Preserve applied migrations, existing signed bytes and retained test environments unless the supported change process explicitly replaces them.

## Package-level checks

After installing locked dependencies, select the package you are changing:

```sh
pnpm --filter @openpc/identity-service check
pnpm --filter @openpc/identity-service test
pnpm --filter @openpc/admin-web check
```

Use the bounded runners on shared evaluation machines. For example:

```sh
bash scripts/maintenance/run-bounded.sh --profile focused -- \
  pnpm --filter @openpc/admin-web test --maxWorkers=2
```

The example is suitable only when the default reservation covers the machine's other work. Account for retained containers with the runner's external-memory option rather than hiding their usage. See [testing](testing.md).

Root commands provide broader validation:

```sh
pnpm format
pnpm lint
pnpm check
pnpm test
```

These commands do not by themselves establish all runtime, browser, recovery or release scenarios. Select the additional checks required by the changed behavior.

## Change an interface

1. Identify the owning schema and all consumers.
2. Describe compatibility, including required fields, enums, errors and authority semantics.
3. Update the schema and implementation together.
4. Run the appropriate generation and validation scripts from [package.json](../../package.json).
5. Review generated changes and test existing consumers as well as new requests.
6. Update the [interface reference](../reference/interfaces.md), examples and release notes.

`pnpm contracts:check` includes linting, validation, dependency checks, generation, manifests and generated-output verification. Generation may write files; start from a known working-tree state and inspect the resulting diff. Do not hand-edit generated files as the sole fix.

### Regenerate module contracts

`pnpm run generate` explicitly selects the versioned public source profile for
module contracts. For a module-only change, use the commands and source-integrity
checks in the [public module source guide](../../policies/modules/source/README.md).
The public profile reproduces the initial contracts from included inputs; it does
not reverify the private historical source package or establish runtime acceptance.
The module package’s historical `generate` and `generate:check` commands retain
their original authenticated-package requirement and do not fall back to public
source when that package is absent.

### Install the contract toolchain

The CI installer supports Linux x86_64. It downloads Buf 1.72.0 and protoc 35.1
from their upstream release pages, verifies the pinned executable hashes and
checks their versions. It needs `curl`, `unzip`, `sha256sum` and `install`.
Run this from the repository root after installing the locked Node dependencies
and the pinned Rust toolchain:

```sh
export OPENPC_CONTRACT_TOOLCHAIN_BIN="$PWD/.openpc-toolchain/bin"
contract_tmp_parent="${XDG_CACHE_HOME:-$HOME/.cache}/tegaris"
mkdir -p "$contract_tmp_parent"
export OPENPC_PNC_TMP_ROOT="$(mktemp -d "$contract_tmp_parent/contracts.XXXXXX")"

bash scripts/maintenance/run-bounded.sh --profile focused -- \
  bash scripts/ci/install-contract-toolchain.sh "$OPENPC_CONTRACT_TOOLCHAIN_BIN"
pnpm contracts:install
pnpm contracts:check
```

Set `OPENPC_CONTRACT_TOOLCHAIN_BIN` to the absolute directory containing the `buf`
and `protoc` executables.
`OPENPC_PNC_TMP_ROOT` must be writable, outside the checkout and outside `/tmp`.
The example creates a separate directory under your user cache. It holds staged
outputs and the AsyncAPI analytics configuration. Keep both directories local and
out of commits. The resource profile must include the machine's retained workloads;
see [testing](testing.md).

`contracts:install` installs the separate AsyncAPI CLI dependencies from their
lockfile with lifecycle scripts disabled and strict peer checks. The root workspace
install alone does not install this independent tool directory. A missing tool,
hash mismatch or dependency-install failure must be resolved before interpreting a
contract check result.

The supplied installer is not a macOS or Windows installer. On another platform,
use the supported Linux development environment or install the same tool versions
for that platform and supply their executable directory. Do not use a Linux binary
on macOS or silently substitute a different compiler version.

## Change persistence

Identify the schema and migration owner. Generate a new migration through that owner's process; do not edit already-applied SQL to make a test pass.

Verify both clean initialization and a populated upgrade. Include failure/restart cases if the migration spans multiple steps or depends on external material. A successful empty-database migration is insufficient evidence for a retained deployment.

Keep original operation identity and durable outcomes intact. Recovery code should reconcile incomplete effects rather than silently issue a new business intent.

## Change the console

Follow the existing components, design tokens and framework conventions. Read the documentation bundled with the installed framework before relying on behavior from another version.

Test loading, empty, invalid, denied, unavailable and stale-response states, not only successful submission. Preserve the link between selected organization, actor, resource and pending request. Check keyboard focus, labels, narrow screens and long identifiers in a rendered browser.

Use task-oriented wording. Explain what the user can do next without exposing private infrastructure, development milestones or implementation diaries. Keep technical details when users need them to identify a resource or make a decision.

### Adapt reusable components

Treat a reused component as part of the console. Match the surrounding typography, spacing, borders, icons and interaction patterns before introducing it into a workflow. Use the color and surface tokens in [the console stylesheet](../../apps/admin-web/app/globals.css), including their light and dark variants. Avoid component-specific color palettes and hard-coded text colors that lose contrast when the theme changes.

Keep presentation separate from authority. A new menu, form section or navigation component must preserve the existing actor, organization, session and request ownership. Disable protected actions until their prerequisites are known. Switching context must clear stale results and prevent an earlier request from updating the new workspace.

| Component           | Expected behavior                                                                                                                                                                                                                                         |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Form sections       | Group related inputs with visible labels and appropriate `fieldset`/`legend` semantics. Explain required values and place errors beside the affected fields.                                                                                              |
| Accordions          | Keep the information needed for the next decision visible. Collapse optional detail only; use a shared disclosure pattern with a clear heading, expanded state, keyboard operation and visible focus. Preserve entered values when a section closes.      |
| Navigation          | Use links for destinations and buttons for actions. Make the current location clear in text or shape as well as color. Preserve the workspace shell during ordinary navigation while showing any required loading or verification state where it applies. |
| Menus               | Support keyboard entry, movement and dismissal. Return focus to the trigger after dismissal, and keep the menu within the viewport at narrow widths.                                                                                                      |
| Status and progress | Distinguish submission, a recorded operation and a confirmed effect. Derive status from authoritative readback. Do not invent progress percentages or success while a result is still uncertain.                                                          |
| Reference values    | Wrap long identifiers or provide an accessible full-value view. Label copy actions and announce their result. Clear old copy feedback when the value or workspace changes.                                                                                |

### Review visible states

Inspect the component in its actual workflow with synthetic data. Include populated, empty, loading, invalid, denied and unavailable states, and any pending or uncertain outcome. Check both themes, long names and identifiers, a narrow phone viewport and a desktop layout. Content and controls must remain usable without horizontal page scrolling.

Complete the workflow with the keyboard, including any opened menu or accordion. Check focus visibility and order, accessible names, error announcements and focus after a dialog closes. Preserve the user's input on recoverable errors; provide a clear next action without exposing private diagnostics.

For review, include the affected rendered states, viewport sizes, keyboard checks and actual workflow results. Component tests and screenshots support this evidence; they do not replace authenticated browser checks for changed session or authorization behavior. State which checks remain unrun.

## Contribute a reviewable change

Explain the problem, resulting behavior, tests performed and remaining limits. Include exact commands or scenario references sufficient for another contributor to reproduce the evidence. Do not turn test counts into a claim of complete product acceptance.

Use synthetic data and your own DCO sign-off. Follow [CONTRIBUTING.md](../../CONTRIBUTING.md), and use a [proposal](proposals.md) for material changes to interfaces, identity, privacy, storage or deployment.
