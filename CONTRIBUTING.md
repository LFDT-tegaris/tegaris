# Contributing

Start with the [development guide](docs/development/README.md). For a substantial change, open an issue describing the problem, expected behavior and proposed approach before writing the implementation.

The [contribution priorities](CONTRIBUTION_PROPOSAL.md) describe useful areas of work. Use the [proposal guide](docs/development/proposals.md) for changes to behavior, interfaces or deployment requirements.

## Pull requests

Keep a pull request focused on one problem. Explain what changes for the user and how you checked it. Include screenshots for visible interface changes and note any remaining limitations.

Run formatting, type checks and tests for the affected packages. Changes to access control, privacy, cryptography or migrations also need tests for rejected inputs and recovery behavior. A UI change should work with the keyboard and show useful loading, empty and error states.

Use synthetic data in examples and tests. Do not commit credentials, customer material, deployment-specific configuration or private diagnostic logs.

## Development practices

- Use the versions pinned in the repository.
- Keep public API contracts and their generated clients consistent.
- Add a migration for schema changes; leave existing migration files unchanged.
- Preserve operation identity when recovering an uncertain write.
- Review dependencies and retain their license notices.
- Keep comments about behavior and constraints; remove redundant narration.

## DCO sign-off

Only submit work you have the right to contribute. Each commit must include your own sign-off under the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

A sign-off certifies the contribution's origin. It is different from a cryptographic commit signature. Do not add another person's sign-off.

Code contributions follow the project's Apache-2.0 licensing commitment. Retain existing copyright and third-party notices.

Documentation contributions use [CC-BY-4.0](LICENSES/CC-BY-4.0.txt), consistent with the [LFDT Labs charter](https://github.com/LF-Decentralized-Trust-labs/governance/blob/main/lf-decentralized-trust-labs_Charter.pdf). Code examples use Apache-2.0. See [licensing](LICENSES/README.md) for scope and third-party notices.

## Review

A committer other than the author reviews each change. Security-sensitive changes need a reviewer familiar with the affected boundary. Reviewers check behavior, compatibility, tests and documentation before merging.

See [GOVERNANCE.md](GOVERNANCE.md) for project decisions and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations. Report vulnerabilities through [SECURITY.md](SECURITY.md), rather than a public issue.

## Prepare your development environment

Follow the [local setup guide](docs/getting-started.md) using the pinned toolchain and a private data directory outside the checkout. Record the base revision and inspect existing working-tree changes before starting. Keep dependencies locked unless the contribution explicitly changes them.

Choose the smallest independently reviewable behavior. Identify the owning component and affected consumers. For a substantial change, use the [proposal guide](docs/development/proposals.md) before implementation; for a focused defect, provide a failing reproduction in the issue or pull request.

## What to include in a pull request

| Item          | Reviewer needs                                                           |
| ------------- | ------------------------------------------------------------------------ |
| Problem       | The actor's task, concrete failure and impact                            |
| Behavior      | The resulting user/API behavior, including rejection and recovery cases  |
| Scope         | Affected components, interfaces, storage and deployment assumptions      |
| Compatibility | Existing clients/data, migration requirements and known breaking changes |
| Validation    | Exact commands or scenarios, results and unrun checks                    |
| Documentation | Updated setup, reference, user, operational and release guidance         |
| UI evidence   | Relevant rendered views, keyboard checks and narrow-screen behavior      |

Keep private operational history and customer material out of the description. Explain the final change as if the reviewer has not read earlier conversations. If scope changes during review, update the description and acceptance criteria.

## Tests and evidence

Follow the [testing guide](docs/development/testing.md). Static checks and unit tests come first; database, runtime and browser evidence are required when the changed behavior crosses those boundaries.

Include denied requests and forbidden effects for access-control changes. Preserve original intent and readback in retry/recovery tests. A test that fails for an unrelated prerequisite does not establish the intended security property.

State limitations directly. A screenshot, a test count or a successfully built image cannot establish complete product readiness. Keep failed or unrun required checks visible until resolved.

## Documentation standards

Write for a developer who has no private project context. Explain prerequisites, actor/role, inputs, steps, expected outcomes, failure handling and cleanup or recovery. Use real supported commands, synthetic examples and links to the relevant contract.

For bank-facing guidance, make trust boundaries, identity/custody assumptions, operational ownership and evidence requirements explicit. Avoid marketing claims, invented performance figures and assertions of regulatory compliance.

Use descriptive headings, consistent terms and tables where they help comparison. Remove repetitive introductions and statements that merely narrate the code. Keep technical identifiers when readers need them to locate an interface or resource.

Run `python3 scripts/docs/check-docs.py` and the applicable formatting check. The checker validates required guides, repository-relative file targets and Markdown section links. Update incoming section links when renaming a heading. A link check does not prove an example works; test commands against the intended environment and record any limits.

## Review and maintenance after merge

Respond to review comments with the resulting correction or a reasoned explanation. Preserve meaningful test evidence when updating the branch. Do not resolve a disagreement by silently removing a required check.

After merge, watch relevant checks and help correct regressions introduced by the change. Update release notes when behavior, configuration or compatibility changes. Security corrections follow the private process until coordinated disclosure is appropriate.
