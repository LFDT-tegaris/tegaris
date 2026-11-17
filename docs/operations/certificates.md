# Certificate and workload identity lifecycle

This guide is for platform engineers and security operators responsible for a development deployment. It explains how to inspect certificate dependencies, prepare a rotation and verify the result. Application developers should use it when investigating an integration that stops authenticating after a certificate change.

Read the [configuration reference](../reference/configuration.md), [interface reference](../reference/interfaces.md) and [operations guide](README.md) with the documentation from the deployed revision. Keep deployment addresses, credential identifiers, issuer records and change evidence in your institution's private operational system.

## Implementation scope

The Identity service implements governed workload certificate issuance, rotation, revocation and certificate readback. It validates the issued certificate against the configured issuer and requested workload identity. Workload certificates have a maximum lifetime of 24 hours in this revision; an institution's longer CA or web-server certificate lifetime does not change that bound.

The local development fixture creates short-lived transport certificates and synthetic issuer material. It does not provide a generally qualified unattended renewal procedure covering every trust relationship in a persistent hosted development environment. Arrange and test the complete lifecycle before relying on that fixture for continuous availability. Changing a fixture's certificate-generation duration does not renew an existing installation.

For an institutional deployment, qualify the selected issuer, credential custody, trust distribution, workload replacement and recovery procedures together. The presence of a rotation endpoint alone does not establish compatibility with a particular enterprise CA, HSM, orchestrator or service mesh.

## Separate the lifecycles

| Material                                | What it establishes                                                        | Owner to identify                                           | Evidence to retain                                                                                              |
| --------------------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Public HTTPS certificate                | The server identity presented to a browser or external application         | Ingress and public-certificate operator                     | Hostname, presented chain, expiry, renewal result and reload verification                                       |
| Internal TLS server certificate         | The server identity presented between services                             | Service operator and issuing PKI                            | Service name/SAN, issuer chain, certificate fingerprint and running consumer                                    |
| Workload client certificate             | The certificate presented by an authenticated workload                     | Workload operator, Identity and issuer                      | Workload/principal/credential binding, certificate fingerprint, validity and authoritative state                |
| Signing-provider transport certificate  | A connection to or from a signing provider                                 | Provider operator and each configured caller                | Server identity, client binding, trust bundle and affected provider attempts                                    |
| CA certificate or trust bundle          | Which issuers a consumer accepts                                           | PKI/trust administrator and consuming service               | Each trust anchor, distribution revision, permitted overlap and retirement condition                            |
| Business signing key and admitted trust | Which key may sign a particular class of application or lifecycle evidence | Signing authority, provider custodian and consuming service | Signer/public-key fingerprint, purpose, grants, credential binding, key epoch and independent validity interval |
| Business authority and session          | Which actions an authenticated actor may perform                           | The relevant authorization owner                            | Scope, epochs, validity, approvals and operation readback                                                       |
| Platform authority ceiling              | The installed upper bound for administration and runtime authority         | Platform governance and installation owners                 | Scope, authority epoch, expiry, current administrator bindings and recovery receipt                             |

A signing key has its own validity interval as well as an admitted workload binding. Inspect both: renewing a certificate does not extend a signing key's lifetime or replace its trust record. Preserve historical public keys and trust snapshots when a new key is admitted.

Renewing public HTTPS leaves internal TLS and workload credentials unchanged. A valid transport certificate also leaves business authorization checks in force. Treat the effective deadline as the earliest relevant expiry across the leaf, its required chain, the admitted credential and the authority needed for the intended operation.

Platform authority ceilings also expire. Record their scope, authority epoch and expiry alongside PKI dates. A completed Root recovery advances the Platform epoch. Recheck the current administrator bindings before continuing with key or certificate work. Certificate issuance and trust-store distribution still require their own validated transition.

For recovery workflows, distinguish the installation record (`INSTALLED`), custody enrollment (`ENROLLED`) and committed recovery operation. The first two stages report `authority: NONE`. Check the committed recovery receipt and current authority bindings before resuming business operations.

## Build the inventory

Start with the service configuration actually running. Follow each certificate, key reference and trust bundle to its consuming process. Include scheduled workers and infrequently used recovery paths, even when the main sign-in page works.

For each connection, record:

- The source service, destination service and expected DNS or URI identity.
- Whether server authentication or mutual TLS is required.
- The mounted certificate and trust references, with their effective running revisions.
- The leaf fingerprint, public-key fingerprint, serial, issuer and validity interval in UTC.
- Every required intermediate and trust anchor, including their expiry.
- The corresponding workload credential and its current admitted state, where applicable.
- The issuer/renewal owner, alert recipient, renewal lead time and fallback procedure.

Use references to keys in approved custody. Keep private keys, tokens, session cookies and issuer authentication material out of inventory exports and public issue reports. A certificate's subject or SAN may itself contain private infrastructure information.

Inspect every certificate in a bundle. The first certificate's dates do not describe the whole bundle. Compare configured files with the certificate presented by the intended running endpoint; a file on disk may belong to another instance or may not have been reloaded.

## Inspect public certificate material

The following OpenSSL examples read certificate files only. They do not issue, install or rotate material. Replace the synthetic filenames and hostname with reviewed values for your environment. Use the OpenSSL version supported by your deployment.

```sh
openssl x509 -in service-server.pem -noout \
  -subject -issuer -serial -dates -sha256 -fingerprint

openssl x509 -in service-server.pem -noout \
  -ext subjectAltName,extendedKeyUsage,basicConstraints,keyUsage

openssl x509 -in service-server.pem -noout -checkend 86400
```

The final command checks a 24-hour expiry horizon for that certificate. A passing result says nothing about another chain member, stored credential state or application permissions. Choose alert thresholds that leave time for approval, issuance, distribution, validation and recovery. Short-lived credentials need an appropriately shorter operating cycle. See the [OpenSSL certificate inspection reference](https://docs.openssl.org/3.0/man1/openssl-x509/).

Verify the intended trust path and purpose using the approved public chain files:

```sh
openssl verify -CAfile trusted-roots.pem \
  -untrusted intermediate-chain.pem \
  -purpose sslserver -verify_hostname identity.example.test \
  service-server.pem

openssl verify -CAfile trusted-roots.pem \
  -untrusted intermediate-chain.pem \
  -purpose sslclient workload-client.pem
```

Omit `-untrusted intermediate-chain.pem` only when the selected chain has no intermediate certificates. Validate the expected workload URI and the application credential binding through Identity as well. Chain verification alone does not check those application-specific conditions. OpenSSL documents [verification options and chain validation](https://docs.openssl.org/3.0/man1/openssl-verification-options/).

Do not add `-no_check_time`, move the system clock or disable certificate validation to recover availability. Classify a failed check and correct its owning certificate, trust configuration, identity binding or clock synchronization.

## Prepare a rotation

Agree the exact workload or connection being changed. A server-certificate renewal, workload credential rotation and CA rollover have different effects and may require different operational steps.

1. **Establish the predecessor.** Read its current credential/operation state, certificate, issuer configuration and consuming process. Resolve outstanding or ambiguous operations before starting a replacement intent.
2. **Check available authority.** Confirm the actor's organization, privacy context, permitted action, resource, current revision and required approval/step-up. Renewing a transport certificate cannot supply missing business authority.
3. **Prepare the successor through its owner.** Use the approved issuer and key-custody process. Check the subject, SAN, public key, usages, chain, validity and deployment references against the intended identity.
4. **Review dependent bindings.** Identify configured credential IDs, certificate/public-key pins, signing-provider clients and issuer-profile digests. Establish how each owner admits a successor while preserving historical requests and evidence.
5. **Plan transition order.** Determine which consumers must trust the successor issuer before it is presented. Define the supported overlap, activation order, health predicates and stop conditions. Use a maintenance window if the tested topology requires one.
6. **Define recovery limits.** Record which configurations/images can be restored, which credentials will be revoked and which business effects are irreversible. Keep prior evidence and public material for authoritative readback.

For a CA change, test trust distribution on every affected consumer. An updated server and one successful client are insufficient when other callers still trust only the predecessor issuer. Retire old trust only after the defined migration and recovery conditions hold.

For a workload change, follow the governed Identity flow. Do not edit a credential's fingerprint, public key, epoch or validity in the database to make new certificate bytes appear to be the predecessor.

### Preflight before time-limited approval

Trace the dependency chain for the exact intended write before acquiring a short-lived approval or recovery lease. A working console, renewed platform authority or successful read may not exercise the credential and key used to sign the eventual write.

Record the following from the effective configuration and authoritative owners:

1. The caller credential actually configured for that operation, its admitted principal/audience, state, epoch and absolute expiry.
2. The provider's presented server certificate, the caller's client certificate, and every CA/intermediate required by their mutual authentication. Check each member's validity and the running consumers' trust references.
3. The selected business signing key for the required purpose, its own expiry, immutable credential binding, admitted grants and current selector revision.
4. The current human or operator authority, approval requirements and operation deadline. Confirm that the planned credential transition can itself obtain the required signatures and provider observations.
5. The original operation and any already recorded provider effect, with the supported readback or continuation path if work is interrupted.

If any prerequisite is expired, stop before consuming the time-limited approval. Qualify the complete affected certificate and signing transition first. A successor leaf signed by an expired required CA, or a new credential still referenced by an old key admission, does not establish usable service trust.

After the prerequisites pass, obtain the necessary short-lived authorization immediately before the intended operation. Record the earliest effective deadline and leave measured time for commit and readback. Preserve prior approvals, keys and receipts; they remain historical evidence even when a new operation needs current authority.

### Check signing-key expiry before preparing a key

An authority-envelope signing key must expire no later than its admitted workload credential. Compare absolute expiry times. Giving the certificate and key the same duration does not align their expiry when they are created at different times.

For example, a credential issued at 09:00 UTC for one hour expires at 10:00 UTC. A signing key prepared at 09:05 UTC for one hour would expire at 10:05 UTC and cannot be admitted under that credential. Select a supported key lifetime that fits within the credential's remaining validity, leaving time for distribution, verification, approved use and recovery.

The local signing provider accepts `OPENPC_SIGNING_PROVIDER_ENVELOPE_KEY_VALIDITY_SECONDS` from 900 to 86400 seconds. This setting applies to newly prepared keys. It does not renew existing keys or credentials, and its upper bound does not establish that a particular duration fits the current credential.

Check the actual admitted credential and presented certificate before starting the operation. If their remaining validity cannot accommodate a supported key lifetime and the planned work, complete the governed credential transition first. Do not change a stored validity interval, move the clock or disable the admission check to make the key fit.

## Workload rotation interfaces

These routes are implemented by the Identity service. Use the configured application gateway and the authentication/authorization conventions from the [interface reference](../reference/interfaces.md). The table is a navigation aid; request schemas and owner responses in the selected revision define the exact contract.

| Request                                                | Purpose                                                                                  |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `POST /v1/identity/workloads/prepare`                  | Prepare an ISSUE, ROTATE or REVOKE candidate and obtain its digest and expected revision |
| `POST /v1/identity/workloads`                          | Submit an authorized issuance request through the configured issuer                      |
| `POST /v1/identity/workloads/:credentialId/rotate`     | Rotate the named predecessor to the authorized successor credential/public key           |
| `GET /v1/identity/workloads/:credentialId`             | Read authoritative credential state within the caller's permitted scope                  |
| `GET /v1/identity/workloads/:credentialId/certificate` | Read the admitted certificate through the applicable authorized read path                |
| `POST /v1/identity/workloads/:credentialId/revoke`     | Submit an authorized revocation                                                          |

A rotation preparation names the predecessor credential, successor credential and successor public key. Preserve the prepared digest, expected revision and resulting operation reference. Complete the approval and authenticator verification required by the returned workflow. Then submit that reviewed intent and reconcile its authoritative result before updating consumers.

If a request times out, read the original operation before retrying. Preserve its original request and idempotency identity. A new idempotency key does not establish that an earlier issuance or rotation failed. Issuer observations and durable owner state must agree before treating the successor as usable.

After a committed rotation, verify predecessor and successor states. Confirm which consumers have switched to the successor and test predecessor rejection according to the operation's semantics. Restoring an old container image does not reactivate a revoked credential.

## Signing continuity during workload replacement

Treat the signing key, its admitted grants and the caller's transport credential as separate dependencies. In this revision, ordinary business receipt signing checks that the caller credential is the credential named in the key's trust record. Keeping the same principal, workload name or public key does not by itself satisfy that check after a credential ID changes.

The ordinary receipt-key rotation flow also checks the predecessor key's credential and its current validity. Its request names one workload credential; it is not a general transfer of a signing key between credentials. A successful workload certificate rotation therefore does not establish that existing receipt keys can sign through the successor. Confirm this before revoking a workload that owns an active signing key.

| Dependency              | Required qualification                                                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Workload credential     | The successor is admitted through the governed Identity flow, with the expected principal, audience, public key, certificate and epoch.                |
| Receipt-key ownership   | The selected signing key admits the actual caller credential through a supported signing workflow; a configuration alias cannot supply that authority. |
| Signing-provider caller | The provider authenticates the successor certificate and permits the intended method, key and scope.                                                   |
| Historical attempts     | Original caller bindings, request bytes and observations remain intact and can be reconciled without resubmitting consumed effects.                    |
| Lifecycle worker        | Key preparation, cutover, observation, revocation and recovery use an independently authorized worker with current credentials.                        |

Automatic workload renewal has additional family, policy, issuer, provider and signing prerequisites. A worker executable or existing renewal tables do not establish an installed renewal policy. Verify the actual admitted configuration and its supported installation path before enabling a worker. Do not populate protocol tables manually to manufacture an approved family, policy, attempt or signing grant.

### Reconcile a successful provider effect after a timeout

The custody provider and Tegaris record their results separately. A request can time out after the provider has changed a key but before Tegaris commits the final operation state. Rolling back the database transaction or restoring an image does not undo a provider revocation or retirement.

Use the original operation and attempt to investigate this condition:

1. Preserve the request, idempotency key, expected revision, approval reference and original operation/attempt references. Retain the first provider response and its binding to the exact key, method and scope in the approved private evidence store. Do not attach private keys or authentication tokens to an issue.
2. Read the operation and affected resource through their authorized interfaces. Record the observed state and time. Keep a missing or incomplete result unresolved; it does not establish that the provider did nothing.
3. Use the owning workflow's supported provider lookup or reconciliation path for that original attempt. Match its key identity, request binding and first observation. Do not issue another prepare, revoke or retire request merely to obtain a response.
4. Compare the provider observation with the durable Tegaris result. If they disagree or the workflow cannot reconcile them, retain the evidence for the responsible maintainer and stop dependent changes. Do not edit protocol tables, manufacture a completion record or reactivate the predecessor to hide the disagreement.

| Observation                                                          | Required interpretation                                                                                             |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Transport failed; provider outcome unknown                           | The effect is uncertain. Investigate the original attempt before another mutation.                                  |
| Provider reports success; Tegaris operation incomplete               | The provider effect may already have occurred. Reconcile its original response with the unfinished operation.       |
| Tegaris reports completion; provider identity or observation differs | Completion is not verified for the intended effect. Investigate the binding mismatch before using or retiring keys. |
| Both report the same completed effect                                | Verify the resulting resource and caller behavior, then retain the linked evidence.                                 |

Check authority expiry separately. An expired approval or recovery lease does not erase a recorded provider effect. Continue only through a workflow that explicitly supports the original unfinished operation under the required current authorization. Changing the clock, stored validity interval or request identity cannot establish that continuity.

The [integration guide](../development/integration.md#separate-submission-from-reconciliation) explains how applications should represent uncertain writes without submitting a second business intent.

### Rehearse a retained-workspace transition

Use an independent synthetic installation with the same affected service revisions and configuration shape. Create its initial trust through the supported bootstrap, then create representative business operations through normal authenticated workflows. Do not copy a live database, private keys, provider attempts or authenticator credentials into the rehearsal.

1. Retain the original operation, receipt, issuer observation and provider-attempt references. Verify their authoritative readback before changing credentials.
2. Exercise the proposed issuer and trust transition, including every internal server and client that uses the affected CA. Preserve the predecessor material required for historical verification.
3. Complete the governed credential and signing transitions in the proposed order. Verify the actual credential used by each caller and worker at every step.
4. Perform a new authorized business operation through the successor. Verify its durable effect, signed receipt, signer trust and operation readback.
5. Exercise rejection of the revoked predecessor, an unrelated credential and a foreign scope. Confirm that denied requests create no business effect.
6. Reconcile a retained pre-transition operation and any deliberately interrupted transition through their original references. Verify that recovery neither duplicates an effect nor adopts another attempt.
7. Restart the affected rehearsal services and repeat successor authentication, a permitted operation and historical readback. Inspect the effective certificates and configuration after restart.

Include expiry in the rehearsal when it affects the intended recovery path. Administrator authorization may remain available after a workload certificate expires, while the signing provider or ordinary key-rotation path may still require the original credential to be current. Establish each boundary independently; do not infer full recovery from a successful preparation request.

Stop before activation if any required owner cannot admit the successor, historical reconciliation fails, an approval expires, or the rollback procedure would require reactivating a revoked credential. Preserve the failed attempt and resolve the missing capability before scheduling a live cutover. Restoring files or an older image cannot reverse an already committed revocation.

## Verify the deployment

Run these checks against the intended instance and retain the result of each required check:

| Check                       | Passing evidence                                                                                    |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| Effective configuration     | Running services use the reviewed issuer, trust bundle, certificate and credential references       |
| Peer authentication         | The intended client verifies the intended server and the server authenticates the intended workload |
| Authority                   | The workload can perform one permitted operation in its intended organization/privacy context       |
| Isolation                   | A foreign-context or unapproved identity is rejected without a business effect                      |
| Predecessor handling        | The old credential is accepted or rejected exactly as the approved transition requires              |
| Original-operation recovery | Existing operation/receipt readback remains available without creating a duplicate effect           |
| Restart                     | A controlled restart keeps the successor configuration and the intended retained state              |
| Monitoring                  | Expiry observations identify the material actually in use and reach the responsible operator        |

Service health, sign-in and a TLS handshake cover different parts of this matrix. Keep failures visible and record any check that could not be exercised. Use representative retained operations to verify history; do not replay a consumed business action merely to produce a new success result.

## Diagnose failures

| Symptom                                   | First boundary to inspect                                                        | Next action                                                              |
| ----------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Expired/not-yet-valid certificate         | The presented leaf, required chain and trusted clock                             | Identify the exact invalid member; arrange supported issuance/transition |
| Unknown issuer or incomplete chain        | The peer's presented chain and the consumer's trust store                        | Correct the reviewed chain/trust distribution, then repeat verification  |
| Hostname or URI mismatch                  | Endpoint identity, SAN and expected workload                                     | Correct routing or obtain the certificate for the intended identity      |
| TLS succeeds but workload is rejected     | Current credential, fingerprint/public-key binding, state and validity           | Reconcile through Identity; verify the proper successor was admitted     |
| Identity succeeds but operation is denied | Organization/privacy context, authority scope, epochs, approval and step-up      | Follow the owning authorization workflow                                 |
| Signing provider rejects a prior attempt  | Original request, authenticated caller binding and retained provider observation | Reconcile the same attempt; preserve its original evidence and identity  |
| Works until restart                       | Persisted service configuration and secret/certificate references                | Correct durable configuration and repeat restart acceptance              |

For suspected key compromise, follow [SECURITY.md](../../SECURITY.md) and the institution's incident procedure. Revocation and recovery may take priority over availability; an ordinary planned renewal does not establish compromise recovery.

## Close the change

Record the exact before/after artifact and certificate identities, issuing owner, governed operation references, approved scope, activation times and affected consumers. Include the authenticated and negative-check results, preserved historical readback and restart result. Record unresolved failures with a responsible owner.

Update expiry monitoring from the effective running material. Retain predecessor evidence according to the institution's retention and custody requirements. The change is complete when the affected consumers use the admitted successor and the required behavior is verified.
