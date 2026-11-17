# Contribution priorities

Tegaris Application Layer Privacy brings identity, contract permissions, disclosure rules and policy review to applications on shared EVM networks. The initial contribution is being prepared in [LFDT-tegaris/tegaris](https://github.com/LFDT-tegaris/tegaris).

We propose developing the code and its documentation together in one repository. This keeps interface changes, tests and examples in the same review. The [approved Lab proposal](https://lf-decentralized-trust-labs.github.io/labs/approved/tegaris.html) describes the project scope.

## Initial contribution

The source candidate includes the administration console, application services, runtime enforcement, shared libraries, interface definitions, database migrations and development tooling. Tests and examples should use synthetic identities and data and run without access to a contributor's infrastructure.

The first source publication is a development release. It does not establish production readiness or qualify every integration. See the [release scope](docs/releases/README.md).

## Where contributions help

| Area                 | Useful contribution                                                      | What a review needs                                                     |
| -------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| First-time setup     | Reproduce the setup guide on a fresh Linux machine and fix missing steps | Tool versions, commands, observed result and a focused correction       |
| Console usability    | Improve a specific task, error message, table or form                    | Before/after views, keyboard checks and narrow-screen behavior          |
| Application examples | Add a small contract example showing allowed and denied requests         | Synthetic data, explicit prerequisites and assertions for both outcomes |
| Privacy tests        | Cover access revocation, expired inputs and cross-organization requests  | Expected decisions and checks that denied requests disclose no data     |
| Event-backed access  | Extend record-access tests and explain freshness and finality behavior   | Reproducible fixtures, failure cases and current limitations            |
| Runtime operations   | Improve activation, upgrade and recovery diagnostics                     | A repeatable failure and evidence that recovery preserves state         |
| Documentation        | Explain a task that currently requires reading the implementation        | Working commands and links to the relevant public contract              |

These are proposed work areas, not promises about release dates. Open an issue to agree on scope before a large change. A small documentation or test correction can go directly to a pull request.

## Working together

Use the [proposal guide](docs/development/proposals.md) to explain the problem, scope and acceptance criteria. Keep discussion in the repository so others can review the decision. Maintainers will help identify the affected components and suitable reviewers.

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for DCO sign-off and review. Security reports belong in the private channel described in [SECURITY.md](SECURITY.md).

## Contribution sequence

### Establish a reproducible setup

The first useful contribution is a setup that an external developer can reproduce from the selected source without private infrastructure or undocumented instructions. Record the environment, commands, failures and corrections. Include a complete allowed/denied journey rather than stopping at service startup.

### Improve one developer or operator task

Choose a concrete task such as diagnosing a denied read, reviewing a policy change or recovering an uncertain operation. Explain the current difficulty and the observable improvement. Update the owning implementation, tests and guide together.

### Extend a supported boundary

Changes to identity, custody, policy inputs, runtime interfaces or disclosure need an explicit compatibility and threat-boundary review. Demonstrate the positive path and relevant foreign-scope, stale, revoked, unavailable and recovery cases. Do not claim provider compatibility based only on a schema adapter or mock response.

### Prepare a releasable contribution

Keep contribution-origin evidence, license metadata, dependency notices and reproducible build inputs with the change. Verify the actual contribution workflow and publish only through the authorized release process. See [RELEASE.md](RELEASE.md).

## What bank engineering teams can contribute

Financial-institution developers can improve the project through synthetic examples of institutional workflows, independent architecture review, realistic failure scenarios, identity/custody integration feedback and reproducible performance studies.

Public contributions should describe the technical need without disclosing customer records, institutional network details, credentials or confidential control designs. Use representative synthetic actors and resources. State whether an example is exploratory, evaluated or operationally qualified, and identify the evidence behind that description.

## Acceptance of a contribution

A contribution is reviewable when another developer can understand the task, reproduce the relevant evidence and identify its compatibility and operational limits. Merging code is distinct from qualifying every deployment or making an official release. Track those later obligations explicitly in the release scope and public issue discussion.
