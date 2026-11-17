# Glossary

These definitions explain terms used in the guides. Machine-readable contracts define the exact fields and states for each interface.

| Term                        | Meaning                                                                                                                                                        |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Activation                  | The process of making a selected release effective at a runtime target; distinct from review approval and publication submission                               |
| Actor                       | The authenticated human or workload performing an action in a particular context                                                                               |
| Approval                    | An authorized review decision about a selected intent or version; it does not prove runtime activation                                                         |
| Authority                   | The permissions and constraints under which an actor may perform an operation                                                                                  |
| BFF                         | Backend for frontend: the console's server-side integration layer and session-oriented request boundary                                                        |
| Canonical representation    | The precisely defined bytes or structure used when computing identities, digests or signatures                                                                 |
| Contract binding            | The association of a logical contract with its relevant network/runtime deployment                                                                             |
| Credential                  | Material or an identity binding used to authenticate; separate from a permission grant                                                                         |
| Definition digest           | A digest of the canonical definition used by a producer and verifier; changing included descriptive text can change this identity                              |
| Decision input / Fact       | An observation used by policy evaluation, subject to provenance and validity requirements                                                                      |
| Disclosure                  | The information an actor is permitted to receive, independently of permission to execute an operation                                                          |
| Durable operation           | A recorded operation whose identity and outcome can be reconciled beyond a single HTTP response                                                                |
| ETag / version precondition | A representation identity used to detect stale or conflicting updates where required by an API                                                                 |
| Evidence                    | Authorized records supporting explanation, investigation or recovery; not inherently public data                                                               |
| Finality                    | The chain/application-specific condition under which an observation is treated as sufficiently settled; distinct from initial submission or inclusion          |
| Governed endpoint           | An interface at which Tegaris applies the relevant identity, policy and disclosure controls                                                                    |
| Idempotency key             | An identifier binding retries to one mutation intent where the interface supports it                                                                           |
| Issuer                      | The trusted identity or certificate authority associated with a credential or assertion                                                                        |
| Organization / participant  | The institutional or application participant context used for access and resource scope; console language may use organization while contracts use participant |
| Platform authority ceiling  | The installed upper bound on the administration and runtime scopes that the Platform may issue, with its own epoch and validity interval                       |
| Policy version              | A selected revision of policy behavior used for validation, review and release                                                                                 |
| Privacy domain              | A contract-defined disclosure/access scope; it is not interchangeable with every organization or network identifier                                            |
| Provenance                  | Information and verification linking an input or artifact to its source and production process                                                                 |
| Publication                 | Submission or distribution of a selected release; not proof that every target has activated it                                                                 |
| Reconciliation              | Determining the authoritative outcome of an existing operation without inventing a replacement business intent                                                 |
| Revocation                  | Removal of previously granted validity or authority; distinct from natural expiry                                                                              |
| Runtime target              | The configured enforcement destination whose identity and activation state must be verified                                                                    |
| Simulation                  | Evaluation of a selected policy and inputs without treating that result as policy activation                                                                   |
| Step-up authentication      | Additional authentication required for the specified operation and validity window                                                                             |
| Workload                    | A non-human application/service identity with its own credentials and granted scope                                                                            |

## Common distinctions

**Authenticated and authorized:** proving identity does not grant every action. A valid login can still receive a legitimate denial.

**Accepted and completed:** an accepted operation may still be pending, require review or have an uncertain downstream result. Inspect its contract-defined state.

**Denied and unavailable:** denial is an access decision; unavailability can mean a required service or input could not establish a result. Neither authorizes bypass.

**Empty and absent:** a permitted empty result does not necessarily prove that no underlying record exists. Disclosure controls can limit what the caller can infer.

**Retry and new intent:** preserving the same supported idempotency context can reconcile a request. A different key or changed payload can create another operation.

**Development fixture and production deployment:** synthetic initial trust makes evaluation possible. It does not establish institutional identity, production custody, operational resilience or regulatory compliance.

## Presentation wording and signed definitions

Use Tegaris in user-facing product guidance. Keep established package names, API fields, schema identifiers and version references where a reader needs them to build or integrate with the project.

A console label can be changed independently of a stored identifier. A signed definition has a different compatibility boundary: the [definition digest implementation](../../packages/security-kernel/src/business-transition/definition.ts) includes its authority rules and other definition fields, excluding only the top-level `definitionDigest` and `signature` fields. Editing a sentence in that object can therefore change the context used to sign and verify records.

Preserve admitted definitions and original signed records. Use the [proposal process for signed-format changes](../development/proposals.md#changes-to-signed-formats) when a change affects those bytes. Historical verification of an original record remains separate from permission to perform a new operation.
