# Security

## Report a vulnerability

Report suspected vulnerabilities privately through [LFDT security intake](mailto:security@lists.lfdecentralizedtrust.org). Put **Tegaris Application Layer Privacy** and the affected repository in the subject. This reporting route is specified by the [LFDT security policy](https://lf-decentralized-trust.github.io/governance/governing-documents/security/).

You may also contact the project directly:

- Ghan Vashishtha: [ghan@zeeve.io](mailto:ghan@zeeve.io)
- Ravi Chamria: [ravi@zeeve.io](mailto:ravi@zeeve.io)

These project contacts are published in the [LFDT Lab proposal](https://lf-decentralized-trust-labs.github.io/labs/approved/tegaris.html). Keep exploit details out of public issues and pull requests.

Include the [report contents](#useful-information-in-a-private-report) below so the response team can reproduce the issue and assess its impact. The team coordinates investigation and disclosure privately with the reporter.

## Security response team

All project maintainers serve on the security response team. The current roster is:

| Maintainer                                            | Email                                                         | Chat ID              | Response responsibility                                 |
| ----------------------------------------------------- | ------------------------------------------------------------- | -------------------- | ------------------------------------------------------- |
| [Ghan Vashishtha](https://github.com/gnv-zeeve)       | [ghan@zeeve.io](mailto:ghan@zeeve.io)                         | Discord: `ghanzeeve` | Report triage, investigation and coordinated disclosure |
| [Supravat Samanta](https://github.com/supravat-zeeve) | [supravat.samanta@zeeve.io](mailto:supravat.samanta@zeeve.io) | Not listed           | Report triage, investigation and coordinated disclosure |
| [Nitesh Sharma](https://github.com/Nitesh-Zeeve)      | [nitesh.sharma@zeeve.io](mailto:nitesh.sharma@zeeve.io)       | Not listed           | Report triage, investigation and coordinated disclosure |

Use the [private reporting routes](#report-a-vulnerability) above to reach the response team. GitHub profile links identify maintainers; public issues and profile comments are not private report channels.

For each report, a response coordinator manages acknowledgment, investigation, reporter communication and disclosure. The coordinator assigns reviewers with relevant component knowledge and engages specialist support when needed. Maintainers keep the reporting contacts and private review access current.

Release maintainers verify the roster and private reporting arrangements during [release preparation](RELEASE.md#prepare-the-source).

Maintainer changes must also update this roster and [MAINTAINERS.md](MAINTAINERS.md).

## Supported versions

The project is preparing its initial source release. There is no stable supported release yet. Release notes will identify supported versions and their maintenance scope.

## Deployment boundaries

Tegaris controls access through its configured application interfaces. Deployments must also control direct access to nodes, databases and supporting services. See the [privacy model](docs/security/privacy-model.md).

Development identity providers and test signing material are for isolated development environments. Production deployments need their own identity, key custody, backup and operational controls.

## Useful information in a private report

Use the following outline. A small, reproducible example is more useful than a complete environment archive.

| Information       | What to include                                                                                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Affected version  | Source revision, release or artifact identity, affected component and relevant configuration.                                                                |
| Security boundary | The actor, required access and intended organization or resource scope. Explain what should have been permitted or denied.                                   |
| Reproduction      | Minimal steps and synthetic inputs, the expected result and the actual result. Include whether the issue survives restart or requires a particular sequence. |
| Impact            | The disclosure or unauthorized effect you observed. Label suspected consequences separately from demonstrated results.                                       |
| Diagnostics       | Sanitized errors, request or operation references and observation times. Include enough context to correlate the failure without sharing active credentials. |
| Mitigation        | Any workaround or correction you tested, its result and remaining limitations.                                                                               |

Explain whether the issue concerns authentication, authorization, disclosure, signing, evidence integrity, dependency execution or recovery. If an operation may have completed despite a lost response, retain its original reference and describe the uncertainty; do not repeat a harmful action to obtain a cleaner report.

Exclude private keys, passwords, active tokens and confidential customer records from the initial report. If additional sensitive material is needed, agree on an appropriate transfer arrangement with the response team first.

## Handling and disclosure

The project assesses the affected scope, coordinates reproduction and develops a correction or mitigation with appropriate reviewers. Regression tests must cover the violated boundary and avoid exposing confidential exploit details before disclosure.

An advisory should identify affected versions, impact, mitigation, corrected versions and verification guidance. Validate the correction on the affected release and deployment path, including a regression test for the original failure.

The [LFDT security policy](https://lf-decentralized-trust.github.io/governance/governing-documents/security/) defines the disclosure timeline: acknowledgment within two business days, an embargo negotiated with the reporter of no more than 90 days when needed, and public disclosure within 48 hours after the corrected release. The response coordinator confirms the private discussion channel and coordinates any advisory and CVE work through the LFDT process.

## Scope of security claims

The [privacy model](docs/security/privacy-model.md) describes the application boundary. Tegaris does not make unrestricted underlying node access confidential. An evaluation must also examine identity-provider configuration, custody, network bypass routes, certificate validity, logs, backups and operational access.

The repository's tests and development fixtures support specific checks; they are not a certification, audit opinion or regulatory compliance statement. Report the exact version and evidence behind any security claim.
