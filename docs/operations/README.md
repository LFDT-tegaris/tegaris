# Operations and recovery guide

Use this guide to assign operational ownership, monitor a running environment and verify recovery. An institutional deployment needs a qualified topology, integrated identity and key custody, tested recovery procedures and named operators. The local fixture provides an isolated environment for developing and evaluating those procedures.

## Maintain an environment record

Keep a private record of source revision, artifact digests, service identities, data roots, network endpoints, identity-provider settings, certificate issuers, secret references and responsible operators. Store secret values separately through the approved custody process.

Distinguish desired configuration from effective running configuration. A changed file or successful deployment command does not prove that traffic reaches the intended instance.

## Readiness and health

| Observation                  | Meaning                                       | Additional verification                                   |
| ---------------------------- | --------------------------------------------- | --------------------------------------------------------- |
| Process/container is running | A process exists                              | Readiness, dependency access and endpoint identity        |
| Health endpoint succeeds     | Its defined health predicate passed           | The affected authenticated user/application journey       |
| Sign-in succeeds             | The tested identity flow completed            | Effective organization access and required operations     |
| Policy publication succeeds  | The publication operation returned its result | Target activation and governed behavior                   |
| Database responds            | A connection/query works                      | Migration state, durable records and recovery consistency |

For a retained development workspace, use `qa-status` from the [configuration reference](../reference/configuration.md). Investigate a specific failing service or operation; do not infer whole-environment health from one HTTP 200.

## Start, stop and restart

Use the supported lifecycle commands with the original data directory. A restart must preserve container/workspace identity, databases, credentials and operation records. Do not initialize a second workspace over the first directory.

### Retained development workspace

Run these commands from the selected source checkout on its supported Linux host. The path in the examples identifies one existing development workspace. Replace it with that workspace's original absolute data directory; use the same value throughout.

First inspect its recorded services:

```sh
bash scripts/operations/policy-testing.sh qa-status \
  --data-dir "$HOME/tegaris-dev"
```

When a stop is part of the planned maintenance, stop through the same helper:

```sh
bash scripts/operations/policy-testing.sh qa-stop \
  --data-dir "$HOME/tegaris-dev"
```

Resume that retained workspace:

```sh
bash scripts/operations/policy-testing.sh qa-start \
  --local-qa-fixture --data-dir "$HOME/tegaris-dev"
```

`qa-start` has two behaviors: it resumes an existing retained workspace when its saved state is present, and initializes a new fixture otherwise. Establish which case applies before using it for recovery. Preserve the original data directory and saved workspace state when moving or restoring an installation. Creating an empty directory with the same name does not restore it.

For an existing workspace, the lifecycle helper checks recorded container IDs, image identities and project ownership before acting. It starts recorded services in dependency order and waits for their running/health predicates. It does not upgrade images, select a new hostname or renew credentials. See the [configuration reference](../reference/configuration.md#data-directory) for directory ownership and permission requirements.

### Interpret the status result

Keep the full status output in the environment's private operating record: it includes local paths and account-file locations. Use the service entries to investigate the affected component.

| Status field or result                         | Interpretation                                              | Next check                                                                                    |
| ---------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `acceptance: "UNVERIFIED"`                     | The helper has not established a complete business journey. | Run the authenticated task and inspect its authoritative result.                              |
| `running: false`                               | The recorded service is stopped.                            | Match this to the intended maintenance/startup state before starting it.                      |
| `running: true`, `health: "healthy"`           | The process and its configured health check pass.           | Verify the required dependency and user/application path.                                     |
| `health: null`                                 | No health result is reported for that service.              | Check its defined readiness contract and the dependent operation.                             |
| An ownership, image or missing-container error | The saved workspace and inspected resources do not agree.   | Preserve the mismatch and establish the correct recovery procedure before changing resources. |

During a recorded maintenance phase, status inspection remains available while ordinary lifecycle changes may be refused. Reconcile or finish the original maintenance phase through its procedure before resuming normal lifecycle commands. Changing the saved maintenance state is not evidence that the work completed.

For a hosted development environment, configure startup through the operating system's service manager and order it after the required network and container services. Exercise an actual restart, verify the same data root and service identities, then repeat sign-in and a relevant operation readback.

Startup may briefly return unavailable responses while dependencies become ready. Wait for the specific startup process and authoritative service states. Do not restart initialization because an early observation returned 502.

## Database installation and upgrades

The local lifecycle helper initializes its databases through the fixture's installation connection. This connection can create database roles and assign function ownership. Keep installation credentials separate from the credentials used by running services.

For an operator-managed deployment, document the account responsible for each database and migration lane, its required permissions, and how those permissions are kept out of application connections. A service account that can read or write its permitted records is not necessarily authorized to install a schema or change function ownership.

| Connection purpose         | Required operating boundary                                                                                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Installation and migration | Apply the selected release's migrations through the supported installer, with the authority required by that migration lane. Protect these credentials and limit their use to installation or approved maintenance. |
| Running services           | Use the configured service identities and scoped permissions. Application connections must not receive database-owner or privileged function-owner membership to make an upgrade succeed.                           |
| Verification               | Inspect the resulting migration records, ownership, permissions and application behavior. Use read-only access where sufficient; identify any stronger access needed for security-catalogue verification.           |

Before upgrading a retained environment, record its current release, ordered migration identifiers and digests, database configuration and recovery point. Rehearse the selected upgrade against an appropriate isolated fixture. A successful fresh installation does not establish that an upgrade preserves existing state.

After installation or upgrade, verify:

1. Every required migration lane completed, and previously applied migration digests remain unchanged.
2. Table and function ownership, role membership, grants and row-level security match the intended release. Check the final state after the complete installer has run.
3. Service connections use their intended identities and can perform an allowed operation while forbidden access remains denied.
4. Original operation records and signed evidence remain readable, and replay or reconciliation returns the original result without creating another effect.
5. The same checks hold after the required service/database restart.

Keep a failed upgrade's original records and diagnostics. Resolve a schema defect through a new migration owned by the relevant schema; do not edit already applied SQL, reset the migration ledger or replace a retained workspace with a fresh fixture. Follow the environment's reviewed recovery procedure if an upgrade leaves its outcome uncertain.

See the [testing guide](../development/testing.md) for qualification scope and the [release procedure](../../RELEASE.md) for release evidence and review.

## Configuration provenance

New public installations select the pinned public schema and named profiles through the [installation configuration source guide](installation-source.md). It explains the separate source, signed-site, installation and effective-generation checks, including retained-record compatibility.

## Certificates and identity material

Track public HTTPS, internal service TLS, signing-provider certificates and business identity/authority validity separately. Each has its own issuer, consumer, expiry and renewal procedure.

The development fixture uses short-lived internal certificates. A public reverse-proxy certificate renewal does not refresh those certificates or any business authority. The repository does not yet provide a generally qualified unattended renewal procedure for every hosted fixture trust relationship.

Use the owning service's supported renewal and recovery workflow, preserving prior issuer records and original signed effects. Keep certificate files, admitted signing trust and business authority consistent throughout the transition. Verify each consumer against the intended identity and authority before resuming operations.

For a proposed rotation, verify the new issuer/material, affected consumers, permitted overlap, rollback conditions and post-rotation authenticated behavior. A successful file replacement is not sufficient evidence that all consumers use the intended identity.

Use the [certificate and workload identity lifecycle guide](certificates.md) for the dependency inventory, read-only inspection commands, implemented Identity routes, transition procedure and verification matrix.

## Runtime policy validity and refresh

A running proxy and a valid client certificate do not establish current runtime policy authority. The installed policy package has its own validity window, in addition to the lifetimes of the identities, grants and source observations used to authorize a request. Restarting a process or refreshing an identity assertion does not extend that package.

### Record the independent deadlines

Maintain the following information in the private environment record. Use UTC and identify the service or operator responsible for each refresh.

| Item                  | Record                                                                                     | Check before continuing                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| Application identity  | Credential reference, admitted state, certificate chain and expiry                         | The intended application can authenticate with its own current credential.              |
| Effective permission  | Workload, assignment, permitted capability and scope                                       | Current authority covers the request and remains within its validity interval.          |
| Published policy      | Immutable version, release and compiled policy digest                                      | The selected release is published; any required fresh approval covers the exact change. |
| Runtime installation  | Target, configuration generation, installed package identity and package expiry            | Current authenticated readback and package evidence agree on the intended installation. |
| Decision dependencies | Provider/configuration references, observation deadlines and required projection readiness | The selected sources are current and correspond to the configuration being activated.   |

The runtime-target read exposes installation state and generation references; it is not a certificate or package-expiry inventory. Obtain package validity from the deployment's authenticated runtime evidence and its owning operator. If that information is unavailable, record the coverage gap and resolve it before promising continuous application access. Keep signed evidence and authentication material in private storage.

Plan renewal with enough time for source revalidation, independent review, deployment and target acknowledgement. Measure those phases in the selected topology. A countdown that covers only the request submission leaves no time to investigate an uncertain result.

### Refresh through the governed workflow

For an already established target, the runtime-target update workflow can request fresh package custody for unchanged configuration. It still creates new work and requires a new target acknowledgement. Use the selected revision's [control API contract](../../schemas/openapi/openpc-control-api.openapi.yaml) for `updateRuntimeTarget`; it defines the exact action intent, request body, revision precondition and returned operation. Existing installed contract-interaction profiles have a separate governed activation path; a generic target update must not silently remove their selection.

1. Read the target and its current revision, installed predecessor and desired configuration through the authorized interface. Resolve any pending or uncertain original work before submitting another intent.
2. Revalidate the selected policy, provider, projection, identity and permissions. Prepare the intended change through its owning proposal and approval workflow. Configuration that is unchanged still needs current authority.
3. Execute the approved request once. Retain its original operation reference and follow that operation's supported readback until the outcome is known.
4. Verify the target's authenticated installation and acknowledgement against the requested generation. Approval, accepted work and process health are separate observations.
5. Authenticate the actual application, run a permitted request and an independently valid request outside its grant, and inspect both outcomes. Confirm that the denied request produces no protected result or effect.
6. Record the new package deadline and verify the same behavior after the required restart or reconnect. Retain the prior package and operation evidence as history.

A policy release's **Activation renewal** task and a runtime-target configuration update are distinct workflows. Select the owner appropriate to the change; use the [integration guide](../development/integration.md#step-4-review-publish-and-observe-activation) for policy-release activation prerequisites. Neither workflow renews the application's certificate or signing key.

### Verify recovery authority before an incident

Check the effective permissions of the named recovery operator in the intended Participant and privacy workspace. A role's display name, a successful sign-in or permission to update a runtime target does not establish permission to recover a policy activation occurrence.

The public occurrence recovery command uses `ACT-FLEET_RECOVER_OCCURRENCE-V1` and requires an action-bound authenticator proof. The operator's current assignment, role and authority envelope must permit that action for the selected occurrence. Verify the same actor and scope through the deployed release's supported authorization and recovery workflow before relying on it during an incident. Keep the original occurrence revision and exact cohort/generation references for the command's concurrency and input checks.

Grant changes must follow the authority model. A new assignment or role cannot add an action beyond its issuing envelope. Typed envelope issuance is bounded by the current installed grantable scope and its validity. Normal scope replacement also remains bounded by the original source lifetime; an expired source cannot provide a future successor deadline. Expiry recovery has separate enrollment, custody and approval requirements. Existing authenticators alone do not establish those requirements.

Record a missing permission or unavailable forward transition as an operating gap. Preserve the pending work and use the reviewed authority or maintenance procedure appropriate to that release. Direct database edits to grants, parked scheduling or signed scope records do not qualify the public recovery workflow.

### Handle expiry and uncertain installation

If a package expires, treat current serving authority as unavailable until the supported workflow establishes it again. An old signed acknowledgement can help establish a historical installation; it does not authorize requests after expiry. Do not infer current access from an old successful response or a matching digest alone.

If work is partial or ambiguous, preserve its original operation, target revision, signed observations and deadlines. Use the owning service's reconciliation path and its actual supported result. Do not retry with a different key, extend a deadline, replace a credential or create another workspace to erase the uncertainty. If that retained state has no supported forward transition in the selected release, report the gap and keep dependent execution unqualified.

Before offering a persistent demonstration, qualify the refresh procedure across its actual validity boundary. An operator-owned procedure and a working one-time update do not establish unattended renewal. Record the responsible operator, renewal lead time, alert delivery and the action to take when renewal is incomplete.

## Module releases and application prerequisites

Use the [module release setup and activation guide](modules.md) to prepare the publisher handoff, deployment catalogue, exact dependencies and independently approved lifecycle changes. Re-read the resulting resource and enabled policy bindings in the intended workspace. Registration, installation and activation are separate states; none replaces current workload credentials or application authority.

## Backup planning

Define the consistency set: databases, durable operation records, configuration, required manifests and identity/key references that must agree after restoration. Determine which private keys are exportable and which are recovered through the custody provider instead.

Use an approved database-consistent backup method. Do not copy a live database directory as if it were a coherent snapshot. Protect backup access and retain the required integrity information without placing secrets in public manifests or build artifacts.

For each backup, record the source environment, revision/schema state, time, scope, storage protection and restore procedure. A successful backup job is not proof that restoration works.

### Define the consistency set

Map the actual deployment before choosing the backup mechanism. The local topology separates these logical PostgreSQL stores; an institutional topology may place them differently.

| State                                      | Include in the recovery design                                                                               | Consistency question                                                                             |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Control database (`openpc_control`)        | Identity, authority, configuration, reviews, operation records and associated evidence/outbox state          | Will an interrupted operation retain its original identity, approved intent and recorded effect? |
| Fact database (`openpc_facts`)             | Required decision-source state, provenance and cursor/checkpoint continuity                                  | Can the runtime establish which observations remain valid and sufficiently fresh?                |
| Candidate index (`openpc_candidate_index`) | Index state or its qualified reconstruction procedure, authoritative profiles and checkpoints                | Does reconstruction preserve the selected scope and chain/finality assumptions?                  |
| Deployment configuration                   | Exact artifact revisions, migration records, endpoint identities, issuer configuration and secret references | Will restored services use the identities and contracts that match the restored records?         |
| Key and identity custody                   | Required key versions, certificate chains, trust pins and custody-provider recovery references               | Can original signed records be verified, and can permitted current identities authenticate?      |
| External systems                           | Identity provider, signing/custody provider, node/provider and application reconciliation records            | Which effects or revocations occurred outside the database recovery point?                       |

Restore each logical database through its owning procedure and verify the relationship between the restored stores. Include role ownership, public privileges, row-level security, constraints and indexes in verification; a row count alone cannot establish equivalent access controls.

Where a cache is used, identify its rebuild and invalidation behavior separately. The local restore contract treats Valkey as a cache that starts empty, not an authoritative source. A missing or rebuilt cache must not produce a permissive authorization decision.

### Specify capture and custody

The deployment's backup procedure should define:

1. **Recovery objective:** the required recovery time and acceptable loss of committed information, with an owner for deciding whether an observed result meets them.
2. **Capture boundary:** how writers are quiesced or how the chosen database-consistent method establishes a recoverable point across the required stores.
3. **Included material:** the databases, configuration, schema/migration identity and custody references in the consistency set, with explicit exclusions.
4. **Protection:** who can create, read, restore and remove a backup; where encryption keys are held; and how retained copies are protected.
5. **Integrity:** how the backup's identity, completeness and required files are checked before restoration.
6. **Expiry and retention:** when the backup may be used, how required historical verification material is retained and how expired copies are handled.
7. **Restore verification:** the destination, isolation controls, reconciliation steps and application checks required before service resumes.

Keep secrets out of the backup inventory itself. An inventory can identify a protected object and its key version without containing the secret value. Record whether custody keys are exportable; a provider-held key may require a provider recovery procedure instead of a file restore.

The repository's local backup contract does not establish a production backup target, point-in-time recovery capability, measured recovery-time objective or measured recovery-point objective. Record those as unverified until the selected topology and procedure have been exercised.

## Restore and recovery verification

There is no universal restore command appropriate to every topology. The selected deployment must provide and test its procedure before production use.

1. Establish the original operation/environment identity and the intended recovery point.
2. Verify the backup and required configuration/custody material.
3. Isolate the recovery destination from conflicting active writers.
4. Restore through the supported database and identity owners.
5. Verify migration state, service identity and authoritative operation records.
6. Reconcile incomplete operations without creating new business intents.
7. Verify authenticated access, disclosure and target state.
8. Record measured recovery time, data-loss observations and remaining uncertainty.

Do not treat a fresh environment with similar records as recovery of the original one. Preserve the original environment and evidence until the recovery decision is complete.

### Verify the restored state in order

| Stage                    | Required observation                                                                                                  | Hold progression when                                                                            |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Destination isolation    | Only the intended restored instance can become a writer or serve the selected traffic.                                | The original writer or another restored copy can still act on the same identities or operations. |
| Data and schema          | The selected recovery point, database identities, migration state and integrity checks agree with the restore record. | A store, migration or required file is missing or from a different recovery point.               |
| Identity and custody     | Service peers, issuers, key versions and historical verification material match their intended use.                   | A certificate is expired, a required key is unavailable or a peer identity differs.              |
| Authority and disclosure | Authenticated allowed and denied requests behave correctly in separate organizations and privacy contexts.            | A restored record grants stale access or reveals another caller's data.                          |
| Operation reconciliation | Original operation references, approvals, effects and external acknowledgements have been reconciled.                 | A submitted write remains uncertain or external effects conflict with the restored database.     |
| Runtime state            | The intended policy/profile version, target activation and relevant chain/finality observations agree.                | A process is healthy but is serving a stale or mismatched configuration.                         |
| Resumption               | The named operator has reviewed the remaining exceptions and the affected application journey passes.                 | A required check is failed, unrun or based only on cached observations.                          |

A database restore does not undo a transaction already accepted by a chain or an external provider. Reconcile those effects using the original operation references and authoritative provider evidence. Starting another submission under a new key can duplicate work that the restored database has not yet observed.

Account for security changes after the recovery point as well: credential revocations, authority epochs, authenticator use, issuer/key rotation and consumed recovery actions may have advanced elsewhere. The restore procedure must establish their authoritative state before allowing new work. Restoring old records is not a renewal or a new approval.

For certificate or credential expiry, follow the [identity lifecycle guide](certificates.md). Restoring files or an earlier database snapshot does not extend their original validity. Retain unavailable checks as unresolved rather than treating the restored service's health endpoint as proof of identity continuity.

### Keep a restore acceptance record

Retain the backup identifier, source and destination identities, selected recovery point, exact artifact/schema revisions, capture/restore times, operators and verification results. Include the original references used to reconcile interrupted work, observed data loss and remaining gaps. Keep the record and sensitive evidence in the deployment's approved private store.

Report measured outcomes separately from targets. A recovery that takes longer than its target is a completed measurement with an unmet objective; an untested restore has no measured recovery time. A successful restart of existing containers is a different result from restoring a backup onto a recovery destination.

## Upgrade procedure

Review release notes, compatibility changes, schema migrations and supported rollback/recovery limits. Test the candidate against both clean initialization and representative retained data.

Record before-images of configuration and the original artifact identities. Apply new migrations through their owner; never edit previously applied migration bytes. After deployment, verify effective versions, readiness, authenticated journeys and retained operation readback.

If rollback would conflict with an applied schema change or completed business effect, use the supported recovery procedure instead of assuming that reinstalling an older image is safe.

## Observability and incident handling

Collect service readiness, resource pressure, dependency availability, operation progress, activation state and certificate-expiry information appropriate to the deployment. Keep genuine authorization/security failures visible; expected test activity should not erase actionable findings.

Use request/correlation identifiers and safe error codes to connect observations. Exclude passwords, cookies, authorization codes, private keys and unnecessary business payloads from logs. Review access to evidence and diagnostic exports.

During an incident, establish the affected instance and user path first. Distinguish observed failure, correlated resource conditions and proven cause. Preserve original operation references and first-failure evidence. Follow [SECURITY.md](../../SECURITY.md) for confidential security reports and [troubleshooting](../user-guide/troubleshooting.md) for diagnostic steps.

### Storage capacity and log retention

Track free space on every filesystem used by the deployment, including databases, operating-system state, container storage and audit logs. In a virtualized deployment, measure both the guest and its physical host.

| Storage owner                           | Growth to measure                                                                    | Recovery requirement                                                                                              |
| --------------------------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Operating system and container runtime  | Writable container layers, image content, snapshots, temporary files and system logs | Keep enough free space for normal writes, the next admitted maintenance operation and its recovery procedure.     |
| Application databases and provider data | Database files, transaction logs, indexes and retained provider state                | Preserve the database consistency set and any externally consumed effects during recovery.                        |
| Audit and application evidence          | Active logs, rotated files, diagnostic exports and archives                          | Apply the deployment's retention and access policy; preserve required historical records before reclaiming space. |

Assign an owner to each capacity threshold. Set warning and critical levels early enough for an operator to act before writes fail or a configured protection stops the host. Choose thresholds from measured growth, peak maintenance demand and response time; a fixed percentage alone may leave too little working space on a small filesystem.

Test that warning and critical events reach the responsible operator. Check measurement freshness, delivery and escalation separately; a running timer and a local status record provide only the measurement. Alert on stale or failed collection as well as low capacity.

When space is critically low:

1. Identify the full filesystem and the actual shutdown or write-failure trigger. Preserve the relevant events before changing retention or restarting services.
2. Hold new builds, imports and other optional writes owned by the affected deployment. Check the impact before stopping a shared service or another workload.
3. Select exact closed log files or other artifacts with a confirmed owner and no active consumers. Check file identity and open writers; an old filename or timestamp does not prove that a writer has closed it.
4. If records must be retained, copy them to the approved archive location, preserve their origin and metadata, verify the copied bytes and make the archive durable before releasing the source. Protect the archive from unintended expiry or cleanup. A second directory on the full filesystem provides no capacity relief.
5. Use each logging service's supported rotation procedure. Preserve active writers and required evidence; avoid truncating active audit logs or using broad container/image/volume cleanup as a substitute for identifying ownership.
6. Measure free space again, confirm logging is active and check service health. Recheck the reserve required for the next operation before admitting it. Assign an owner to unresolved storage growth and alert-delivery failures.

Emergency reclamation provides time to correct the cause. Complete the capacity change, supported retention configuration or data-placement correction, then verify growth and alert delivery over the agreed observation period. An encrypted archive on the same host still needs the separate backup and custody arrangements described above.

## Operational acceptance

Before a wider deployment, demonstrate startup, restart, backup restoration, upgrade, certificate/credential renewal and representative failure recovery for the named topology. Assign ownership for unresolved checks. Development health and a working sign-in page are useful milestones, not substitutes for this evidence.
