# Governance

Tegaris Application Layer Privacy operates under [LFDT Labs governance](https://lf-decentralized-trust-labs.github.io/governance.html).

## Project decisions

Use issues and pull requests for technical proposals, design discussions and decisions. Describe the user problem, alternatives, compatibility implications and the evidence behind a recommendation.

Committers seek agreement through review. If a proposal remains disputed, record the open questions and decision in the issue before merging.

## Responsibilities

Committers maintain the code and documentation, review contributions, triage issues and coordinate releases. The initial project contacts are listed in [MAINTAINERS.md](MAINTAINERS.md).

A contributor cannot approve their own change. Changes affecting authorization, privacy, cryptography, migrations or public contracts need review by someone familiar with that area.

## New committers

Contributors can become committers through sustained contributions and review. Existing committers discuss nominations openly and coordinate repository access with LFDT staff.

## Releases

A release identifies its source revision, scope, known limitations and installation instructions. Published binaries and container images should include dependency notices, an SBOM and build provenance.

Release descriptions must distinguish implemented behavior from planned or unverified behavior. Changes to external interfaces and deployment requirements belong in the release notes.

## Community

The [LFDT Code of Conduct](CODE_OF_CONDUCT.md) applies to project participation. Follow [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Decision records

Record the problem, alternatives, accepted scope, responsible owner, required reviewers and validation criteria in a public issue or proposal. Distinguish a proposed direction, an accepted design, a merged implementation and a released capability.

When an unresolved disagreement affects correctness, security or compatibility, keep the competing positions and evidence visible and seek the relevant maintainers' review. This document does not invent voting rules or override LFDT Labs governance. Questions requiring LFDT authority should be taken through its established governance process.

## Review responsibilities

| Responsibility       | Expected work                                                                                   |
| -------------------- | ----------------------------------------------------------------------------------------------- |
| Contributor          | Provide a focused change, contribution-origin sign-off, reproducible evidence and documentation |
| Reviewer             | Evaluate behavior, scope, compatibility and failure cases independently of the author           |
| Component maintainer | Assess changes to the owned contracts and consumers and help resolve regressions                |
| Release maintainer   | Assemble the exact candidate, validation record, notices and publication evidence               |
| Security responders  | Handle confidential reports and coordinated remediation through the configured private process  |

Repository access, a listed contact and a security-response assignment are different things. Confirm responsibilities and access before relying on them operationally. Do not infer a response commitment from a person's appearance in a proposal.

## Releases and compatibility decisions

The release maintainer should identify the candidate revision and affected compatibility boundaries. Reviewers evaluate the actual source and artifacts, not only a release checklist. Required failures, unsupported scenarios and unresolved operating limits remain visible in the release notes.

A change to required API fields, authority semantics, persistent state or recovery behavior needs an explicit compatibility decision. Source publication does not automatically qualify official binaries, container images or a production topology.

## Maintainer changes and continuity

Nominations should describe sustained technical contributions, review quality and willingness to maintain an area. Record the outcome and coordinate access through authorized repository and LFDT administrators.

When responsibilities change, update [MAINTAINERS.md](MAINTAINERS.md), review ownership and operational contacts. Remove obsolete access through the authorized process. Avoid leaving a security or release responsibility dependent on an unavailable individual.

## Public and private discussion

Technical design, ordinary defects and roadmap decisions should be reviewable by the community. Vulnerability details, credentials, customer data and private infrastructure information belong in the appropriate confidential process. Publish a useful sanitized explanation when disclosure is appropriate; do not publish raw private incident records.
