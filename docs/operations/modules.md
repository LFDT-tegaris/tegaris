# Module release setup and activation

Use this guide to prepare the modules required by an application policy. It covers the release publisher's handoff, the deployment operator's catalogue configuration, and the administrator's registration, installation and activation tasks.

Module activation is one prerequisite for a policy journey. Workload credentials, authority assignments, contract definitions, policy publication and target activation have their own lifecycles. A healthy service or an active module does not establish that an application request is authorized.

## Responsibilities and prerequisites

Agree the required module set and its dependency closure for the selected release before submitting changes. Obtain the exact release evidence from the publisher; a module name and version alone are insufficient.

| Responsibility       | Required preparation                                                                                            | Result to retain                                                           |
| -------------------- | --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Release publisher    | Produce the artifact, manifest, configuration and signed release evidence through the selected release process. | Exact manifest digest, version, dependency identities and evidence bundle. |
| Deployment operator  | Configure the deployment-owned release catalogue and its trusted publishers; verify compatibility and validity. | Catalogue/trust references, selected profile and artifact identities.      |
| Requester            | Use the intended organization and privacy workspace with authority for the proposed operation.                  | Reviewed request, original operation and approval references.              |
| Independent reviewer | Review the same immutable intent using a separate authorized account.                                           | Recorded decision and its exact approved inputs.                           |
| Application owner    | Confirm enabled bindings, workload authority and the intended policy/runtime behavior.                          | Authoritative readback and allowed/denied request evidence.                |

Before beginning, check the source/documentation revision, intended environment, organization and privacy workspace. Confirm that requester and reviewer can complete their required authenticator verification. Use the deployment's approved credential process; module setup does not renew an expired workload certificate or establish a new trust root.

## Keep module identities distinct

Several identifiers appear in this workflow. Preserve their complete values and types.

| Identifier                        | Meaning                                                                              | Where it is used                                              |
| --------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| Module name                       | The named module contract, such as a `pc.`-prefixed name from the selected registry. | Publisher handoff and **Module name** during registration.    |
| Exact version                     | The release's semantic version, without a range or a floating alias.                 | Registration and dependency resolution.                       |
| Manifest digest                   | The `sha256:`-prefixed digest of the exact admitted release manifest bytes.          | Registration, release verification and dependency binding.    |
| Resource reference                | The returned `urn:openpc:resource:…` identifier for the scoped module record.        | Resource readback, installation and activation.               |
| Revision                          | The current resource revision, represented as a decimal string.                      | Review and concurrency checks for installation or activation. |
| Operation and approval references | The original governed request and independent decision.                              | Reconciliation, effect inspection and support.                |

The generated [module registry and manifests](../../policies/modules/README.md) describe the checked-in contracts. They do not prove that a module is registered or enabled in a running workspace. A release process can bind supply-chain evidence and exact dependency digests into the release manifest, so do not substitute a template's digest for the publisher's final release digest.

## Prepare the publisher handoff

For each selected release, obtain the following through the approved distribution channel:

1. The module name, exact version, final manifest digest and intended support/profile compatibility.
2. The manifest and executable artifact, configuration bytes, software bill of materials, provenance and build receipt.
3. The signed release payload and signature envelope, with the publisher identity needed for verification.
4. The exact dependency names, versions and manifest digests, including dependencies of dependencies.
5. The supported execution hosts, deployment profile and configuration constraints.
6. The publisher trust validity and the procedure for a rejected, expired or revoked publisher.

Keep the bundle immutable. Resolve any mismatch between manifest, artifact, receipt, signature or dependency identities with the publisher before proceeding. Do not replace a rejected artifact with another file under the same name or change an expected digest to make verification pass.

Repository integration fixtures can generate synthetic signed bundles for isolated tests. Those fixtures and their test signers are not a production release pipeline or an approved institutional publisher. Use the selected release's reviewed build, signing and distribution process for a persistent deployment.

## Configure the deployment catalogue

The policy service uses a deployment-owned catalogue to resolve the exact manifest digest submitted for registration. Requests do not supply artifact paths or publisher trust.

| Configuration selector               | Purpose                                                                                                                                          |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POLICY_MODULE_RELEASE_CATALOG_FILE` | The catalogue containing the supported release entries and their evidence-file references.                                                       |
| `POLICY_MODULE_RELEASE_TRUST_FILE`   | The manifest/schema and stack compatibility, deployment profile, execution-host and publisher-trust configuration used to verify those releases. |

Configure these selectors together. The service rejects a partially configured pair. An unset catalogue does not become configured when an administrator enters a manifest digest in the console.

The catalogue uses schema version `1.0.0`. Each release entry identifies `manifestDigest` and the files for `manifestBytes`, `artifactBytes`, `sbomBytes`, `provenanceBytes`, `buildReceiptBytes`, `configurationBytes`, `payloadCbor` and `coseSign1`. Release evidence must resolve inside the catalogue directory. Protect that directory and the trust configuration from unauthorized writes, and keep publisher private keys outside the catalogue.

The trust configuration selects the manifest schema and its digest, the stack lock digest, target profile, admitted execution hosts and publisher public keys with state and validity intervals. Installing a public key file by itself does not register a module or grant a user authority. A publisher must remain acceptable when the service verifies the release.

Changing catalogue or trust configuration is a deployment operation. Prepare it through the selected deployment procedure, retain the preceding configuration and assess affected consumers before applying it. This guide does not prescribe an unqualified hot reload or service restart.

## Complete each governed request

Registration, installation and activation each have their own reviewed intent and approval. For each operation:

1. As requester, enter its details and choose **Review request**. Inspect the exact inputs and resulting candidate before requesting approval.
2. Select an independent reviewer, or enter the **Independent checker principal ID** if the workflow asks for it. Choose **Request approval** and retain the returned approval reference.
3. The reviewer signs in with their own account and opens **Activity** for the same workflow. Use **Read approval and result** with the original approval reference. Inspect the operation, resource, candidate and intended effect, then use **Approve with security key** if the request should proceed.
4. As the original requester, read the same approval and result. When the approved candidate is usable, choose **Execute approved request** and complete the required authenticator interaction.
5. Read the original operation and resource after execution. Distinguish a successful command from the resource's resulting lifecycle state before starting the next operation.

Keep the requester's original sign-in session available. Execution can be bound to the session that prepared the request; signing in again or renewing the session is not evidence that an earlier candidate can execute in the new session. Follow the displayed original-request/readback procedure if the session changes. Do not replace a still-fresh approval or an uncertain operation with a duplicate request.

## Register the exact release

In **Contracts & ABI**, choose **Create change**, then select **Register a module release**.

1. Enter the publisher's **Module name**, **Exact version** and **Manifest digest**.
2. Select the supported **Support profile**. The current console offers the contract value `R1`; selecting it does not establish that every product journey has passed release qualification.
3. State the operational reason and choose **Review request**.
4. Review the organization, privacy workspace, module identity, exact digest and proposed effect. Complete the normal request and independent approval sequence shown by the console.
5. Read the original request and resulting resource. Retain its resource reference, current revision, operation reference and approval reference.

Resolve the exact dependency closure in dependency order. A dependency must be available in the same intended scope with the required version and manifest digest. The service verifies releases and their dependencies; registration is not permission to ignore a missing or incompatible dependency.

Registration readback should identify the intended release as **Registered**. This is not an installed or active module. Do not infer success solely from an approval decision, a submitted request or a resource reference displayed before the operation's effect is confirmed.

## Install the registered release

Use **Technical references** to read the registered module resource and its current revision. Then choose **Create change** and **Install a module release**.

1. Enter the returned **Resource reference**, its current **Expected revision**, and the reason.
2. Choose **Review request**. The console reads the release and binds the lifecycle input to its current identity, revision and manifest digest.
3. Review the exact operation and complete its independent approval and authentication requirements.
4. Read the original operation and the module resource again. Confirm **Installed** and retain the new revision.

Installation leaves the module inactive. Use the new authoritative revision for the next operation; do not assume that the revision entered for installation remains current.

If a review reports stale state or a revision conflict, inspect the current resource and the original request. Establish whether another authorized operation changed the resource before preparing a new request. Never change only the expected revision of an already approved intent.

## Activate the installed module

Activate required dependencies before their consumers. Re-read the selected installed module, then choose **Create change** and **Activate an installed module**.

1. Enter its **Resource reference**, current **Expected revision**, and reason.
2. Review the exact module and proposed activation.
3. Complete the independent approval and required authenticator interaction.
4. Read the original operation and the module resource. Confirm **Active**, the intended manifest identity and the new revision.
5. Return to the policy/RPC workflow and reload its authorized configuration. Confirm that the required enabled module bindings are now available in this privacy workspace.

An enabled binding includes the module identity, version, manifest digest and configuration digest. Use the current owner-provided bindings for policy authoring. Do not construct them from a directory listing or substitute another organization's configuration.

## Interpret the result

| Public resource state | What has been established                             | What remains separate                                                        |
| --------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------- |
| `REGISTERED`          | The scoped release has been admitted and retained.    | Installation, activation and application authority.                          |
| `INSTALLED`           | The install operation completed for that module.      | Activation and current enabled configuration.                                |
| `ACTIVE`              | The module is enabled through its lifecycle owner.    | Policy version, approval/publication, target activation and workload access. |
| `DISABLED`            | A governed disable operation has disabled the module. | Assessment and reconciliation of affected policies and consumers.            |

These are module-resource states. They are different from the state of an operation, an approval, a policy version or a runtime target. Read each record through its owning contract.

## Continue to the application policy

Before creating an immutable policy version, confirm:

1. Every required module binding is enabled in the selected privacy workspace with the intended configuration.
2. The intended roles exist, and the proposed workload has the necessary current credential and governed role/capability assignments.
3. The contract definition, ABI, deployed-network binding and method policies match the real test contract.
4. The policy uses the exact owner-provided references and only methods supported by the selected runtime.
5. A separate authorized reviewer can inspect the exact version and proposed release.

Use the [console guide](../user-guide/README.md) for policy authoring and release, the [integration guide](../development/integration.md) for governed requests, and the [validation plan](../evaluation/README.md) for allowed/denied behavior and effect evidence.

Module activation alone does not make an expired workload selectable or authorize RPC. Check the [certificate and workload identity guide](certificates.md) for credential validity, and inspect the workload's actual assignments and envelopes before changing access.

## Diagnose a blocked step

| Observation                                            | Check next                                                                                                                                                                             |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A digest cannot be resolved during registration        | Confirm that the deployment catalogue contains that exact final manifest digest and its complete evidence bundle.                                                                      |
| A release or dependency is rejected                    | Check exact version/digest, signature and publisher validity, schema/stack/profile compatibility, and dependency scope. Preserve the original error and request reference.             |
| Installation or activation reports stale state         | Read the current module resource and the original operation. Use a new review only after reconciling whether an earlier effect occurred.                                               |
| A protected read is unavailable while signed in        | Check organization/privacy context, authority and any required existing-authenticator verification using the [troubleshooting guide](../user-guide/troubleshooting.md).                |
| Registration succeeds but policy bindings remain empty | Confirm installation, activation and active configuration in the same privacy workspace. Registration by itself is insufficient.                                                       |
| Bindings load but no workload can be selected          | Check the intended workload's current credential and the relevant assignment/capability requirements. Do not treat an active principal record as proof of a valid workload credential. |
| A request times out or its result is unknown           | Preserve its original operation, approval and inputs. Read the original result before retrying; a new request identifier does not establish a new business intent.                     |

Keep private deployment paths, credentials, publisher private keys and confidential inputs out of public issue reports. Report a small synthetic reproduction, the selected revision, the failed step and a redacted request reference.

## Interface and verification references

The module resource API exposes these routes; use the [interface reference](../reference/interfaces.md) for transport, authentication and request contracts. An operation body without its required authorization and approval context is not a complete request.

| Task                               | Route                                         |
| ---------------------------------- | --------------------------------------------- |
| Browse registered module resources | `GET /api/v1/modules`                         |
| Read one module resource           | `GET /api/v1/modules/:moduleId`               |
| Prepare registration               | `POST /api/v1/modules/proposals`              |
| Execute approved registration      | `POST /api/v1/modules`                        |
| Prepare installation               | `POST /api/v1/modules/:id/install/proposals`  |
| Execute approved installation      | `POST /api/v1/modules/:id/install`            |
| Prepare activation                 | `POST /api/v1/modules/:id/activate/proposals` |
| Execute approved activation        | `POST /api/v1/modules/:id/activate`           |

Use the full returned resource reference for the route identifier. Module names and manifest digests are not substitutes for that resource reference. Preserve decimal revision strings without converting them through a floating-point number.

For acceptance, retain evidence of the exact signed release, dependency closure, independent approval, final resource readback and current policy bindings. Exercise a rejected incompatible release and a stale revision in an isolated evaluation environment. A passing manifest validator or an **Active** label does not replace the complete authenticated application journey.
