# Release process

This guide covers source releases and official binaries or container images. Release maintainers are responsible for selecting the candidate, recording its validation, obtaining independent review and verifying the published result.

The first public source import and artifact publishing workflow are still awaiting verification. Until those steps are complete, use the documented source setup; official binary and container download instructions will be added when available.

## Prepare the source

1. Select a source revision and define its supported use, included components and limitations in the [release notes](docs/releases/README.md).
2. Confirm contribution rights, DCO sign-offs, license metadata and third-party notices for the exact files being published. Each contributor supplies their own sign-off.
3. Check the candidate for credentials, confidential records, prohibited generated binaries and dependencies on private files or services. Include the configuration, schemas and generation inputs needed to build from the public checkout.
4. Follow the [setup guide](docs/getting-started.md) from a fresh Linux checkout using the pinned toolchain and dependency locks. Build the included components and run the applicable formatting, type, unit, contract and integration checks.
5. Exercise the supported console journeys in a browser, including keyboard access, narrow screens, and loading, empty and error states. Confirm that the user documentation matches the candidate.
6. Verify the [security response roster](SECURITY.md#security-response-team), private reporting delivery and response coverage. Confirm each responder's chat identifier, technical area, LFDT security-list membership and access to the private fix-review process, including specialist contacts.
7. Obtain review from a maintainer other than the author. Resolve release-blocking findings before selecting the final revision.

Record each check's result against the revision it covered. Keep failures and unrun checks visible, with their effect on the supported release scope. Reuse passing results when their source and environment remain applicable; changes after review require checks for the affected behavior.

## Candidate record

Maintain one record for the candidate so reviewers can trace the release decision to its source and evidence.

| Area              | Record                                                                                         |
| ----------------- | ---------------------------------------------------------------------------------------------- |
| Source            | Revision, selected files and components, dependency locks and generation inputs                |
| Licensing         | Contribution rights, sign-offs, license declarations and third-party notices                   |
| Build             | Toolchain, environment, setup commands and results from an independent checkout                |
| Behavior          | Applicable positive, denial, privacy, browser, migration and recovery results                  |
| Operations        | Supported topology, certificate and credential lifecycle, and tested continuity procedures     |
| Security response | Confirmed roster, private intake, coverage, specialist contacts and private fix review         |
| Documentation     | Setup, integration, reference, operations, release notes and migration guidance                |
| Distribution      | Proposed locations and, for binaries or images, digests, SBOM, provenance and signing identity |
| Limitations       | Known issues, failed or unrun checks, unsupported scenarios and release-blocking findings      |

## Independent review

The reviewer works from the stated release behavior and requirements, inspects the candidate, and reproduces the selected setup and user journey using the public instructions.

Review identity and participant isolation, operation and disclosure permissions, stale or unavailable decision inputs, original-operation recovery and populated migration behavior where applicable to the release. Check the actual test selection and results as well as the implementation. Record the reviewed revision and any conditions on approval.

## Publish a source release

The first public source release is **v0.9.0**, published with GitHub's prerelease flag. Its supported scope and known issues are defined in the [v0.9.0 notes](docs/releases/v0.9.0.md). An authorized maintainer creates the tag only after the source, contribution and review checks above are complete, then publishes the corresponding source archive and release notes. Keep the preparation status in the documentation until that publication is verified.

The repository release tag identifies the complete source snapshot. Component package versions, API versions and database revisions retain their own compatibility identities. Do not rewrite dependency locks or applied migrations merely to align their numbers with the repository tag.

Keep the first public import separate from private development history. Where that history lacks DCO sign-offs, follow the [LFDT Labs import instructions](https://github.com/LF-Decentralized-Trust/lab-proposals#if-you-have-an-existing-repository). Confirm contribution rights before import; creating a new import commit does not establish those rights.

## Publish binaries or images

Establish a reproducible build and approved publishing workflow before distributing official artifacts. For every artifact, publish:

- Its version, platform, source revision and cryptographic digest.
- Dependency notices and a software bill of materials generated from the resolved build.
- Build inputs and provenance.
- A signature or signed attestation following the [LFDT release-signing policy](https://lf-decentralized-trust.github.io/governance/governing-documents/release-signing/).
- The artifact location, expected signing identity and exact consumer verification commands.

Test the download and verification instructions from a separate consumer environment. Verification must bind the artifact to its expected signer or workflow identity and source revision. A checksum detects changed bytes; the signature and provenance establish the additional identity and build information.

Add distribution URLs, signing identities and commands only after the actual publishing path has been exercised successfully.

## CI and publication separation

Contribution checks run without release credentials or production access. Publishing uses a separately authorized workflow with restricted refs, minimal permissions and appropriate environment protections.

Pin external workflow dependencies to reviewed immutable revisions and review their updates. Untrusted pull-request code must not execute in a privileged publishing context, receive publishing credentials or execute on persistent internal runners.

Verify branch protections and required-check names in the repository settings. Exercise a failing test and a missing sign-off before recording those controls as enforced.

## Release-note structure

Include the following information:

1. Version, date, source revision and artifact identities.
2. Supported use and deployment scope.
3. User-visible additions, corrections and removals.
4. API, configuration, dependency and persistent-state compatibility changes.
5. Upgrade prerequisites and supported rollback or forward-recovery limits.
6. Completed validation and material unrun or unsupported scenarios.
7. Known issues, operating limits and security guidance.
8. Links to installation instructions, consumer verification, SBOM, notices and provenance, where available.

Describe behavior and limits concretely. Claims of production readiness or compliance require a defined scope and supporting evidence.

## Post-publication readback

An authorized maintainer independently checks the public tag, source archive, release notes and distributed artifacts. Confirm that downloads and documentation links work, and that the published revision and digests match the reviewed candidate.

Record discrepancies and address them through a corrected version or the security advisory process. Continue tracking regressions, dependency findings and changes to the supported scope after publication.

## Corrections

Preserve published artifacts and release tags. Issue a new version for corrections, identify affected versions and provide upgrade guidance. Follow [SECURITY.md](SECURITY.md) when a correction addresses a vulnerability.
