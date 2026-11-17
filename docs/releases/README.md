# Release scope

The first public source release is planned as **v0.9.0**. Its [release notes](v0.9.0.md) define the release scope, known issues and remaining publication checks. It has not yet been tagged or published.

The initial source contribution is a development baseline for application-layer privacy and policy administration.

The code covers identity and access administration, contract configuration, policy lifecycle, governed RPC interfaces, runtime coordination and supporting console workflows. The availability of a module does not establish that every integration or deployment configuration is qualified.

## Current limitations

- The initial release is intended for isolated development and integration testing.
- Event-backed visibility and some integration scenarios are still being validated.
- Production key custody and operational deployment require separate qualification.
- Interfaces may change while the project develops.

Each tagged release should identify its source revision, supported setup, completed validation, known issues and upgrade instructions. Binary distributions should include dependency notices, an SBOM and build provenance.

The [roadmap](../../ROADMAP.md) describes the next areas of work.

## Plan an integration

Assign an application engineer, an identity or security owner, and an operations owner to the integration. Agree on the permitted data, network boundaries and success criteria before connecting institutional systems. Start with synthetic users and contracts in the supported isolated development environment.

| Area                               | Review and evidence to retain                                                                                                                                                                                                                                                               |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reproducible setup                 | Record the source revision, pinned tools, machine resources, setup commands and service status. Another engineer should be able to repeat the [local setup](../getting-started.md) from those records.                                                                                      |
| Identity and administrative access | Identify the person and workload accounts, selected organization and privacy domain, maker/checker separation, authentication requirements and grant limits. Verify permitted and denied actors in the [console workflows](../user-guide/README.md).                                        |
| Application integration            | Map each required contract method to its read or write behavior, disclosure policy and approval path. Record exact inputs, request identifiers and the final operation and resource state using the [integration guide](../development/integration.md).                                     |
| Disclosure boundaries              | Identify which application data may be returned, to whom and under which conditions. Test foreign organizations, insufficient grants, filtered responses and evidence exports against the [privacy model](../security/privacy-model.md).                                                    |
| Recovery and retained data         | Exercise lost responses and restarts with the original request identity. Verify that the durable outcome, signed history and business-effect cardinality remain correct. Use the [testing guide](../development/testing.md) and supported [operations procedures](../operations/README.md). |
| Credentials and key custody        | Agree on trust distribution, provider custody, credential expiry, renewal, revocation and emergency ownership. Evaluate transport credentials and signing authority separately using the [certificate guide](../operations/certificates.md).                                                |
| Operations                         | Define monitoring, backups, restore procedures, capacity, incident ownership and maintenance windows for the selected topology. Retain observed results from the [operations guide](../operations/README.md).                                                                               |
| Release and change control         | Review the exact release contents, dependency notices, known issues, compatibility and upgrade instructions. Use the maintainer's [release procedure](../../RELEASE.md) to understand the expected release evidence.                                                                        |

Keep a test record for each scenario: actor and context, preconditions, input, expected result, observed result, operation or resource identifiers, failure/recovery outcome and source revision. Record an unexecuted scenario as open. A successful sign-in, component test or one integration path does not replace the other agreed criteria.

Share synthetic reproductions and redacted results with the project. Keep account files, private keys, customer records and institutional infrastructure details in the institution's approved systems.

## Development environment

Use isolated Linux development environments, synthetic identities and test data. Inspect architecture and privacy assumptions, reproduce selected workflows and contribute corrections. Keep the source and documentation revision aligned.

The local development environment starts with synthetic identity data. Institutional onboarding, production key custody and enterprise identity-provider integration require separate validation. For a hosted development environment, plan certificate renewal, capacity and operational ownership before inviting users.

## Qualification still required

Before an institution relies on a production deployment, the selected release/topology needs documented evidence for its identity and custody integrations, runtime enforcement, disclosure controls, failure recovery, retained-data upgrades, backups, certificate lifecycle and operational ownership.

Performance and availability claims need measured workloads, hardware and failure conditions. No service-level objective or production support agreement is implied by this development baseline.

## Version and compatibility policy

Version v0.9.0 identifies the first public source release. Mark its GitHub release as a prerelease. A 0.x version does not establish a stable public API; review the release notes before every upgrade. Package versions, API versions, database revisions and runtime policy versions are separate identities and may evolve differently. Existing component versions are not renumbered solely to match the repository release tag.

An apparently additive API change can still affect consumers if it changes requiredness, enum handling, authorization or result semantics. Migration and rollback limits must be recorded explicitly. Do not downgrade a deployment across incompatible applied state merely because an older image is available.

## Reporting a qualification gap

Record the exact revision, topology, scenario, expected result and observed outcome. Distinguish a product defect from missing setup, an unsupported feature or an unrun check. Submit a synthetic reproduction through [SUPPORT.md](../../SUPPORT.md), or use [SECURITY.md](../../SECURITY.md) for a suspected security boundary failure.

## Upgrade scope

The initial public release provides no supported upgrade path from pre-release installations. Subsequent release notes must identify supported published baselines and the migration, compatibility and recovery evidence for each upgrade path.
