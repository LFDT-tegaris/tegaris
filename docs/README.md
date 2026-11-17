# Tegaris documentation

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/tegaris-logo-light.svg">
  <img src="assets/brand/tegaris-logo-primary.svg" width="256" height="56" alt="Tegaris">
</picture>

Tegaris Application Layer Privacy governs application access to shared EVM networks. These guides are written for application developers, platform engineers, security architects and reviewers evaluating the project, including teams working in financial institutions.

The source is a development baseline. A documented interface or available component is not a claim that a deployment has passed production qualification. Read the [release scope](releases/README.md) before selecting a version or planning an integration.

For the first release, start with [onboarding](../ONBOARDING.md) and the [v0.9.0 getting-started checks](releases/v0.9.0.md#getting-started-checks). The broader sequence below describes subsequent validation stages; completing them is not assumed by the v0.9.0 label.

## Choose a starting point

| Your responsibility                      | Start with                                 | Then read                                                                                       |
| ---------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| Explore the demonstration                | [Demo guide](demo.md)                      | [Sample data](examples/demo-data.json), [console guide](user-guide/README.md)                   |
| Evaluate the architecture                | [Architecture](architecture.md)            | [Privacy model](security/privacy-model.md), [validation plan](evaluation/README.md)             |
| Build an application integration         | [Local setup](getting-started.md)          | [Integration guide](development/integration.md), [interface reference](reference/interfaces.md) |
| Administer a development workspace       | [Console guide](user-guide/README.md)      | [Troubleshooting](user-guide/troubleshooting.md)                                                |
| Operate a hosted development environment | [Hosted demo](development/hosted-demo.md)  | [Operations guide](operations/README.md), [configuration reference](reference/configuration.md) |
| Contribute code or documentation         | [Development guide](development/README.md) | [Testing guide](development/testing.md), [contribution rules](../CONTRIBUTING.md)               |
| Review a proposed design                 | [Proposal guide](development/proposals.md) | [Privacy model](security/privacy-model.md), [governance](../GOVERNANCE.md)                      |
| Prepare a release                        | [Release process](../RELEASE.md)           | [Release scope](releases/README.md), [licensing](../LICENSES/README.md)                         |

## Recommended validation sequence

1. **Establish the boundary.** Identify the application traffic Tegaris will govern and any direct node or database access outside that boundary.
2. **Run an isolated workspace.** Follow the setup guide with synthetic data and retain the exact source revision and tool versions.
3. **Complete one user journey.** Register a contract, define a narrowly scoped policy, simulate allowed and denied inputs, obtain review and inspect runtime activation.
4. **Connect a test application.** Admit its workload identity, grant the necessary authority and use the configured governed endpoint.
5. **Exercise failures.** Test foreign-organization access, revocation, stale inputs, timeouts and recovery before broadening the integration.
6. **Assess operating requirements.** Review identity-provider integration, key custody, certificates, backups, observability, upgrade procedures and support ownership.
7. **Record an evidence-based decision.** Separate successful checks, failed checks, checks that were not run and capabilities outside the selected release.

The [validation plan](evaluation/README.md) supplies a review structure and scenario matrix. It is an engineering review aid, not a certification or a declaration of regulatory compliance.

## How to use these guides

The architecture and privacy guides explain responsibilities and assumptions. Setup and console guides describe human tasks. Integration and interface guides cover application behavior. Operations covers continuity and recovery. Development and testing explain how to change the implementation without breaking those contracts.

Use the [glossary](reference/glossary.md) for project terms. _Approved_, _published_, _active_ and _finalized_ refer to different states; treating them as interchangeable can lead to incorrect integration decisions.

For public installation provenance, signed site configuration and source-verification failures, see [Installation configuration sources](operations/installation-source.md).

For signed releases, dependency setup and governed registration, installation and activation, use the [module operations guide](operations/modules.md).

Operators responsible for persistent environments should also read the [certificate and workload identity lifecycle guide](operations/certificates.md). It covers separate HTTPS, service TLS, signing-provider and admitted workload lifecycles, with inspection commands and rotation acceptance checks.

Machine-readable schemas in the selected revision define fields and validation rules. Prose explains their use. If a guide and a schema disagree, preserve the reproduction and report the mismatch; do not weaken validation to match an example.

Examples use synthetic organizations, contracts and identifiers. Replace configuration through the supported setup process. Do not copy development credentials or signing material into another environment.

For a tagged release, use documentation from the same tag. Keep the source revision, image digests and documentation revision together in test records. Development-branch documentation may describe changes absent from an older binary or image.

For interaction analyses, signed observations, method grants and profile activation, use the [Contract interactions guide](user-guide/contract-interactions.md). It includes field formats, schema-checked examples, state interpretation and recovery of an uncertain request.

## Help and feedback

Use [SUPPORT.md](../SUPPORT.md) for questions and reproducible defects. Follow [SECURITY.md](../SECURITY.md) for suspected vulnerabilities. Public reports should contain the smallest useful synthetic example, with credentials, personal data and private infrastructure details removed.

## Advanced development references

The [local Compose guide](../deploy/compose/local/README.md) explains the test environment, migration ownership and retained-state operations. Read its [secret handling guide](../deploy/compose/local/secrets/README.md) before inspecting or moving environment material.

The [experimental administration CLI](../apps/admin-cli/README.md) has separate opt-in checks and incomplete command coverage. Its documentation describes the implemented authentication and readback paths without treating it as a supported release interface.
