# Testing and validation

Select tests that cover the changed behavior, its permitted outcomes and its failure paths. Record what each check covers. Acceptance of a deployment requires the complete application journey as well as its component checks.

## Test layers

| Layer                      | What it can establish                                                    | What it does not establish alone                     |
| -------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------- |
| Formatting, lint and types | Source consistency, static checks and selected interface compatibility   | Runtime authorization or persistence behavior        |
| Unit/component tests       | Local decisions, state transitions and component behavior                | Full identity, database and provider interaction     |
| Contract tests             | Request/response shapes and boundary validation                          | Correct deployment configuration                     |
| Database/integration tests | Behavior through actual persistence and service owners                   | A complete browser journey or external qualification |
| Browser tests              | Rendered tasks, interaction, session handling and accessibility checks   | Unexercised backend outcomes                         |
| Recovery/upgrade tests     | Retained-state behavior across specified transitions                     | Every failure or topology                            |
| Release qualification      | The named source/artifact under the recorded deployment and scenario set | Universal production readiness                       |

## Start with a reproducible failure

Describe the actor, organization, input, current state, expected result and forbidden effect. For a mutation, identify the intended durable result and how to read it back. Preserve the original failing case before applying the correction.

Use synthetic identities and data. Keep denial cases independent: wrong role, foreign organization, expired credential and live revocation should each exercise the intended predicate. A test rejected for an earlier unrelated reason does not prove the later boundary.

## Focused commands

Examples from the repository's current package scripts:

```sh
pnpm --filter @openpc/identity-service check
pnpm --filter @openpc/admin-web check

bash scripts/maintenance/run-bounded.sh --profile focused -- \
  pnpm --filter @openpc/admin-web test --maxWorkers=2 \
  components/workbench.test.tsx

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/docs -p 'test_*.py' -v
python3 scripts/docs/check-docs.py
```

The documentation checks cover required files, local targets and Markdown sections. They also reject links to headings that exist only in fenced examples or hidden comments. When renaming a heading, update its incoming links according to [GitHub's section-link rules](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#section-links). These checks run in the Documentation workflow and do not start application services.

The resource example assumes no unaccounted retained workloads. Use the documented runner options and actual inventory to reserve external memory and disk. Do not start several independent heavy commands merely because each has a local cap.

### Sign-in pages

Run the demo identity-provider page checks with the pinned Node version:

```sh
node --test tests/integration/local-runtime/oidc-signin.test.mjs
```

These checks create temporary synthetic accounts and an HTTP provider, then close the provider and remove its test directory. They cover labelled controls, rejected and expired requests, a safe return to sign-in, consumed nonces, callback binding, PKCE and one-time authorization codes. The root unit command includes them. Use the browser and authorization suites separately to validate a complete workspace sign-in.

For Rust changes, use the affected crate's tests during development, then the required workspace checks for the integrated candidate. The CI configuration records the exact formatting, Clippy and test commands and their resource profiles. Preserve the lockfile and pinned toolchain.

### Installation configuration sources

The [source verification guide](../operations/installation-source.md#contributor-verification) identifies the public, database-free checks and focused native installation fixture. Native qualification uses actual signed site documents and an installation-only database login. Keep source authentication, staged generation and effective runtime readiness as separate assertions.

## Broader checks

The root unit command includes a real Chromium virtual-authenticator registration
test. Install the browser version pinned by the locked Playwright dependency and
its operating-system libraries before running the full suite on Linux:

```sh
bash scripts/maintenance/run-project.sh -- \
  pnpm exec playwright install --with-deps chromium
```

This prerequisite is required even when selecting the unit command without the
full browser journey suite. A missing browser is an environment failure, not a
reason to skip authenticator verification.

```sh
pnpm format
pnpm lint
pnpm check
pnpm test
pnpm contracts:check
```

Contract checking includes generation and can write outputs. Inspect the resulting working-tree changes. Root `test` combines its configured unit and resource checks; read the scripts before assuming it includes every runtime or browser scenario.

## Automated policy activation and withdrawal

The convenience helper runs an isolated browser and runtime test of initial policy activation, withdrawal and renewal failure after expiry. It selects a shorter journey than the full governed-RPC suite. Use it to check that initial policy authority is established and withdrawn through the selected workflow; evaluate application requests separately through the [integration guide](integration.md).

### Prepare and run

Complete the Linux prerequisites and locked dependency installation in the [setup guide](../getting-started.md). Install the pinned Chromium browser and its operating-system libraries before starting. Use a dedicated development machine with the required build and runtime capacity. Retained workloads still count toward that capacity.

Choose a private data directory outside the checkout, separate from any manual console workspace:

```sh
bash scripts/operations/policy-testing.sh run \
  --data-dir "$HOME/tegaris-policy-test"
```

The helper checks the toolchain, builds the selected images, initializes an isolated environment and runs the selected journey. Initial identity trust is synthetic; subsequent actions use the journey's authenticated application and browser flows. Let the command return its result before starting another build or test.

Each invocation creates a new `local-runtime.*` directory under the data directory's `runtime` child. Repeating the command is a new test, not recovery of a previous operation. The command leaves its diagnostic services stopped after the journey. Use `qa-start --local-qa-fixture` with a separate data directory when you need a console that remains available for manual testing.

### Recognize a completed run

A passing command returns exit status zero and finishes with:

```text
Policy activation and withdrawal checks passed. Retained diagnostic containers are stopped; see <private log>.
```

The log records progress and the retained environment. These markers have different meanings:

| Log entry                                                     | Meaning                                                                                                            |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `OPENPC_FIRST_SOURCE_ACTIVATION\|PASS\|...`                   | The selected initial activation, withdrawal and renewal-failure journey reached its success boundary.              |
| `OPENPC_RETAINED_ENVIRONMENT\|...\|state=stopped\|...`        | Cleanup stopped the owned diagnostic environment and retained its files. This can also appear after a failed test. |
| `OPENPC_RETAINED_ENVIRONMENT\|...\|state=cleanup_failed\|...` | Cleanup could not confirm the expected stop. Preserve the environment and investigate before starting another run. |

Read the command's final exit status as well as the markers. A journey can reach its success boundary and then fail cleanup. Healthy services, an earlier passing phase or a stopped diagnostic environment alone do not establish a passing test.

This command does not reach the full suite's `OPENPC_FIRST_POLICY_RPC` completion marker. It does not establish complete governed-RPC, disclosure, custody, database-recovery or institutional-onboarding acceptance. Use the affected integration and recovery suites for those obligations; keep the [validation matrix](../evaluation/README.md) aligned with the checks actually run.

### Locate and protect the results

The helper prints its private log path at startup. Logs are retained as `logs/run.*.log` under the chosen data directory. The retained-environment marker identifies the exact runtime root; use that root rather than assuming the newest directory belongs to the interrupted process.

Within that runtime root:

| Location                      | Contents and use                                                                               |
| ----------------------------- | ---------------------------------------------------------------------------------------------- |
| `evidence/`                   | Diagnostic output collected during setup and the journey.                                      |
| `evidence/runtime-bootstrap/` | The initial policy journey's requests, responses, actor/session material and browser evidence. |
| `data/`                       | Retained configuration and database state used by the isolated environment.                    |
| `secrets/`                    | Generated test credentials and signing material. Keep the entire directory private.            |

Evidence can contain tokens, synthetic credentials, signed requests and confidential payloads when adapting a test. Keep the complete runtime root in protected storage. Share only a reviewed, redacted reproduction with the source revision, failed phase and safe error details. Do not attach the data directory or a raw evidence archive to a public issue.

### Investigate a failed or interrupted run

Preserve the first failure and its private log. Identify whether the failure came from prerequisites, capacity, image preparation, initialization, the selected workflow or cleanup. Record which phase completed and whether the original process is still running. A quiet log or an interrupted terminal does not prove that its child processes have stopped.

If a request was submitted, reconcile its original operation through authorized readback before another mutation. Keep its identifiers, signed bytes and observed outcome. Do not delete volumes, alter migration records, recreate credentials or rerun the command to erase an uncertain result.

Check the retained-environment marker and actual owned container state separately. If stop was not confirmed, resolve the original process and cleanup ownership before allocating another environment. Follow the [operations guide](../operations/README.md) for retained-state handling and [troubleshooting](../user-guide/troubleshooting.md) for common setup and access failures.

For a fresh test after the cause is understood, retain the original run and record the new source revision and any configuration changes. A new passing case does not change the outcome of the failed or interrupted one.

## Minimum behavioral matrix

| Change             | Include                                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------------------------- |
| Access or identity | Authorized actor, wrong role, foreign organization, expiry, revocation and recovery                       |
| Policy lifecycle   | Selected version, stale/conflicting version, independent review, publication and target activation        |
| Disclosure         | Allowed fields, withheld fields, collections, errors, exports and events where applicable                 |
| Mutation/retry     | First success, exact replay, conflicting replay, lost response, durable readback and restart              |
| Decision inputs    | Valid, missing, stale, invalid-provenance and reorganized inputs where applicable                         |
| Persistence        | Clean initialization, populated upgrade and interrupted/resumed operation                                 |
| UI                 | Loading, empty, validation, denial, unavailable and stale-response states; keyboard and narrow-screen use |

## Numeric precision and signed bytes

Use the field types defined by the selected interface. Keep decimal-string identifiers, epochs and counters as strings throughout a test. For database serialization vectors, pass literal JSON text to PostgreSQL so that parsing it in JavaScript cannot round a large integer or discard its decimal scale.

Write the expected representation independently and compare both the returned text and its UTF-8 bytes. Include these boundaries:

- SQL `NULL`, JSON `null`, booleans and empty strings.
- Integers around `2^53`, the `uint64` maximum, decimal scales, signed zero and exponents.
- Quotes, backslashes, control-character escapes, combining characters and non-BMP Unicode.
- Object-key ordering, duplicate-key normalization, array order and nested or empty containers.

Keep retained JSON values inside the database when comparing serializer versions. Passing them through a client JSON parser can change the values before the comparison. Order result rows by a stable source key with the correct type; a text-formatted ordinal sorts `10` before `2`.

For signed outputs, retain the original payload, signature and verification key. Check the actual producer's bytes with the intended consumer, including a tampered-signature denial. Record byte equivalence separately from current authorization, credential validity and the resulting business effect.

## Qualify governed RPC results

The [RPC result helper](../../tests/integration/local-runtime/rpc-result.mjs) separates response classification from case acceptance. It is test support, not a production client or authorization component. Its [tests](../../tests/integration/local-runtime/rpc-result.test.mjs) provide examples for permitted responses, typed denials, filtered results and transport failures.

`classifyRpcResponse(request, response)` checks the JSON-RPC envelope, matching request ID and the expected denial fields. Pass a response object with `status` and the parsed JSON `body`. It returns `RESULT`, `DENIAL` or `FAILED`; a `RESULT` does not establish correct disclosure or a completed write.

`qualifyRpcCase` additionally requires two assertion callbacks:

| Input                 | Responsibility                                                                                                          |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `expected`            | Select `allow` or `deny` from the case's agreed policy expectation                                                      |
| `request`, `response` | Supply the actual request and observed response                                                                         |
| `verifyFixture`       | Assert that the intended identity, resource, policy and runtime setup were effective for this request                   |
| `verifyOutcome`       | Assert the returned data or authoritative decision/effect readback for this exact case                                  |
| `denyRepresentation`  | Use the default `TYPED_DENIAL`, or explicitly select `POLICY_FILTERED_RESULT` when the policy permits a filtered result |

Both callbacks may be asynchronous. They must complete without a return value when their assertions pass and throw when an assertion fails. Returning `true` or `false` is rejected so that a bare flag cannot substitute for asserted evidence. The outcome callback receives the response classification; it can also use the response and durable references captured by the test.

A missing or failed fixture assertion returns `BLOCKED`. A transport/envelope mismatch or failed outcome assertion returns `FAIL`. A missing outcome callback returns `BLOCKED` after successful classification. Only verified fixture, expected response kind and successful outcome assertions produce `PASS`.

Test an empty result according to its meaning. `null`, `[]` and `0x` are not automatically policy denials. A policy-filtered response still needs assertions for its permitted projection; a timeout or authentication failure must never count as proof of privacy enforcement.

Run the focused tests with the pinned Node.js version:

```sh
node --test tests/integration/local-runtime/rpc-result.test.mjs
```

The suite also runs through the root `test:unit` command. Its unit cases use assertion doubles and do not prove that a deployed runtime enforces a particular institution's policy. Live tests must supply real fixture and outcome readbacks.

## Provider response fixtures

The [provider header fixture](../../services/multi-rpc/tests/fixtures/README.md) contains fabricated hashes, an address and a transaction reference. It exercises the RPC decoder and indexer response filter without distributing a customer network capture.

These Rust tests check closed field types, consistent timestamps, preservation of permitted header fields, removal of provider extensions and rejection of unexpected payloads. Keep shape checks separate from chain verification: a well-formed fixture does not prove canonicality, execution or finality. Live provider compatibility needs its own authenticated observations.

## Temporary identity fixtures

Identity TLS and authenticator fixtures create disposable test material in unique temporary directories. They honor their configured test-directory overrides and otherwise use the operating system's temporary directory. The TLS fixture checks `OPENPC_TEST_TMP_ROOT`, then `OPENPC_LOCAL_RUNTIME_TMP_ROOT`; the authenticator emulator checks `OPENPC_LOCAL_RUNTIME_TMP_ROOT`.

The bounded runner supplies owned test directories. When running a helper directly with an explicit override, create the parent directory first. Keep generated private keys and certificate material out of the source tree and public attachments. Use each fixture's cleanup function after closing its consumers; on failure, retain only the diagnostics needed for investigation and protect any remaining test keys.

Changes to these helpers should be checked through their real TLS or attestation consumers. Exercise the configured-directory path and the standard temporary-directory fallback, including the existing invalid-certificate, foreign-trust and altered-attestation cases. Generating a certificate alone does not establish that a consumer validates it correctly.

The Identity integration driver selects the database allocation before creating its container:

| Selected journey                  | PostgreSQL RAM cap | CPU limit | Process limit | External-memory admission               |
| --------------------------------- | ------------------ | --------- | ------------- | --------------------------------------- |
| Identity-envelope signer recovery | 4 GiB              | 1 CPU     | 256           | 4.5 GiB                                 |
| Other focused Identity journeys   | 1 GiB              | 1 CPU     | 256           | At least 1.5 GiB for the database phase |

Each database sets its combined memory-and-swap limit equal to its RAM cap, leaving no swap allowance. Signer recovery runs HTTP readback and worker transactions against the same database. Its larger allocation accommodates their concurrent query plans. The bounded runner must also admit host build and test processes and any other containers. These test limits are not production sizing or measured performance guarantees.

When a PostgreSQL backend disappears, check its container's memory events and the host's kernel records as well as the container status. A backend can be killed by its memory limit while the database container remains running. Preserve the failed run and [reconcile the original operation](#failure-handling-and-reporting) before another write. A capacity correction requires enough admitted external memory; it does not justify changing credential validity or approval requirements.

## Workload certificate rotation rehearsal

The [workload rotation integration test](../../tests/integration/identity/postgres-workload-certificate-rotation.test.ts) creates an independent CA and synthetic predecessor and successor certificates. Its pre-allocation check verifies real signatures, chain, workload URI, keys and expired/current validity intervals. It also exercises actual mTLS envelope-provider lookup before database allocation, accepting a canonical response and rejecting a noncanonical frame. The native journey installs initial signing trust while the predecessor is current, waits for natural expiry, then rotates it. No retained keys or certificates are used, and the system clock is unchanged.

Run the native rehearsal from the repository root with the pinned toolchain, Docker and the database phase's required capacity:

```sh
bash scripts/maintenance/run-bounded.sh \
  --profile database --external-memory-gib 1.5 --peak-disk-gib 40 -- \
  bash tests/integration/identity/run-participant-readback.sh \
  tests/integration/identity/postgres-workload-certificate-rotation.test.ts
```

The driver installs a disposable database and uses actual runtime roles, Identity, Policy, an external HTTP issuer and synthetic authenticator keys. Only initial trust is installed directly. Candidate preparation, maker/checker approval, authenticator assertions, credential effects and readback use their normal owners. The test checks denial before approval, exact replay without another issuer request, rejection of changed input, foreign-organization isolation, preserved predecessor certificate bytes and persisted successor readback after an Identity restart.

The predecessor's expiry is deliberate. Recovery authority belongs to the current human administrators; an expired workload certificate supplies no authority. The historical successor proof is checked through the actual Identity database role, including rejection under an unrelated runtime signing key and unchanged proof after restart.

The [initial signing fixture](../../tests/integration/identity/workload-signing-handover-fixture.ts) contains seven independent keys: five business-effect keys, one lifecycle-evidence key and one authority-envelope key. Their exact grants cover 18 receipt selections and one envelope selection, including module-management profiles and both admitted indexer-profile versions. Only initial public trust is installed directly; private signing material stays outside the control database.

The source-capture checks run after natural certificate and key expiry. They authenticate the original public trust, committed native successor proof, current administrator authority and exact selection versions under a serializable transaction. Omitted keys, altered roles, wrong environments, action digests and trust digests must fail. The generated selection-lock permission must permit a consistency read while the existing guard rejects a direct selector update. Repeat capture after Identity restart and compare the same source document.

These checks establish credential rotation and historical signing-source capture. Complete handover also requires fresh possession proofs, approval of the exact admission candidate, atomic successor trust and selection changes, and signed business operations before and after the transition. Existing provider attempts, unattended renewal and deployed installations need their own qualification. Use the [certificate operations guide](../operations/certificates.md) to plan those dependencies.

### Preparation custody

The same native journey exercises the [handover preparation store](../../services/identity-service/src/db/workload-signing-handover-store.ts) through the actual database role after native authentication and source verification. It records one scoped, immutable request and seven exact provider-preparation commands. The checks cover:

- Concurrent preparation and exact replay retain one original intent, source digest and recording identity.
- Changed input, a foreign organization and a changed provider binding cannot replace the retained records.
- Attempts retain the successor caller, key purpose, provider, original identifiers and canonical bytes. Direct updates are rejected.
- Recording attempts creates no successor-key trust or signing grants. Request and attempt readback remain stable after Identity restarts.

The [provider preparation component cases](../../services/identity-service/src/domain/workload-signing-handover-provider.test.ts) check both protocols, complete scope and epoch bindings, response timing, current key metadata and explicit provider rejection. Run these smaller checks before allocating a database:

```sh
bash scripts/maintenance/run-bounded.sh --profile focused -- \
  pnpm --filter @openpc/identity-service exec vitest run \
  --config vitest.config.ts src/domain/workload-signing-handover-provider.test.ts
```

### Provider dispatch and observation recovery

The [dispatch owner](../../services/identity-service/src/domain/workload-signing-handover-dispatch.ts) commits a unique, immutable dispatch claim before making an external request. The command keeps its original operation, attempt, caller and provider binding. A subsequent invocation looks up that exact attempt; it does not issue the command again. A crash after claiming an attempt but before sending it leaves an unresolved intent. An absent provider response is insufficient authority to replay it or choose another key.

The native test uses the production receipt and authority-envelope clients against an [independent synthetic mTLS provider](../../tests/integration/identity/workload-handover-provider-fixture.ts). Both connections verify the certificate chain and use TLS 1.3; the envelope client also verifies its configured server public-key pin and canonical response framing. The provider independently reads the committed dispatch record before accepting a command. Faults are introduced only at this external boundary.

The [observation store](../../services/identity-service/src/db/workload-signing-handover-observations.ts) appends scoped canonical results with a contiguous digest chain. It validates each response against the retained command, including its original identifiers, caller, reference, purpose and provider. Readback verifies every entry. The connected checks cover:

- A provider completes an attempt but loses the response. Lookup recovers its original answer without another dispatch.
- Concurrent invocations retain one dispatch claim. A committed claim whose command was never sent remains unresolved after an absent lookup.
- A genuine rejection stays distinct from transport uncertainty. A later missing, malformed or unavailable lookup cannot erase a confirmed answer.
- Two different, valid answers for the same immutable attempt produce a persistent conflict. Receiving the first answer again does not clear that conflict.
- Foreign-scope reads and changed provider bindings fail. Direct record updates and a forged canonical observation append fail through the actual runtime database role.
- Original observations and their digest chains survive Identity restart. After the maker ends the session through the normal logout interface, fresh dispatch authorization fails while lookup can still retain a delayed historical response.
- Preparation and observation recovery create no successor signing-key trust or grants.

Observation custody is independent of present authority: a delayed response remains historical evidence after a browser lease or key expires. Current key readiness is checked separately. Fresh possession, exact maker/checker admission, atomic trust and selection changes, signed business continuity, populated upgrades and governed forward recovery remain separate qualification obligations. A stored command, dispatch claim or valid inspection response cannot confer signing authority.

### Successor-key possession

The [possession generation owner](../../services/identity-service/src/db/workload-signing-handover-possession-store.ts) requires successful, consistent preparation readback for the complete selected bundle. Every key must have a distinct fresh fingerprint and reference, the intended purpose and the exact successor identity. Missing, rejected or conflicting preparation results block generation creation.

A generation records the complete source digest, issuer identity and epochs, original preparation commands and observations, and a server-clock challenge window. The window is at most five minutes and ends no later than the issuer credential or any prepared key. Random server nonces and each proof command's original identifiers are retained before external I/O. The challenge binds these fields to the complete generation; a signature for another generation, purpose, key or caller is insufficient.

The generation and every proof command commit together. A deferred database guard rejects an incomplete bundle through the actual runtime role. Legacy preparation commands keep their original bytes and identifiers; possession commands have distinct child identities and their own canonical digest. Proof construction uses the normal business/lifecycle and authority-envelope `PROVE` protocols. It does not use the envelope repair protocol or an expired predecessor credential as current authority.

Historical readback must return the same authenticated record through the collector and transaction entry points. The native regression compares all seven original preparation histories through both paths, including a full authorized caller context. Observation records contain the participant and privacy-domain identifiers; caller authorization objects and verifier functions do not become part of their canonical bytes.

The synthetic provider retains its own private keys outside Identity and signs with the key returned during preparation. The native journey checks actual mTLS execution and P-256 verification, invalid-signature and lost-response handling, exact replay, changed input, foreign scope and restart readback. It then waits for the real five-minute challenge deadline:

- An unsettled original proof blocks a replacement generation.
- A delayed original result can still be collected and verified as historical evidence after the deadline. It supplies no current readiness.
- Fresh dispatch under an expired generation is rejected. Directly inserting an incomplete generation also fails at transaction commit.
- After all original proofs settle successfully, an explicit current-maker request can create a successor challenge generation for the same prepared keys. The previous generation is superseded; its document, commands, signatures and observations remain unchanged.

The expiry case deliberately takes at least five minutes, in addition to database initialization and native setup. Keep its longer timeout scoped to that case. Do not extend credential or key lifetimes, change the system clock, edit recorded deadlines or skip expiry to make the suite pass.

If this native journey fails, the runner stops its owned database and retains its private fixture material under `secrets/` in the diagnostic scratch directory. This includes synthetic credential, signing and authenticator keys needed to inspect the original state. Keep that directory private, preserve its ownership and never include it in public CI artifacts. Successful runs clean their owned state; uncertain ownership or failed cleanup retains it for investigation.

These checks establish possession custody and the tested settled-generation refresh path. They create no successor signing-key trust, grants or selection changes. Native approval of the complete admission candidate, its independently authorized first signed evidence, atomic activation, signed business operations, public API/console delivery, populated upgrades and complete forward recovery remain separate obligations. A possession signature proves control of a private key; it cannot authorize that key's grant.

### Exact admission candidate and approval

The [admission candidate owner](../../services/identity-service/src/db/workload-signing-handover-admission-store.ts) stages the complete review document in the existing immutable mutation-candidate store. It reads the retained source, current successor credential and audience, original preparation records and every successful possession proof. The caller supplies the generation identity and digest, action semantic digest and reason. Descriptors, profile grants, source snapshots and readiness flags are captured by the server.

Admission uses the explicit `ACT-WORKLOAD_SIGNING_HANDOVERS_ACTIVATE_RESOURCE-V1` permission and `ID-OP-WORKLOAD-SIGNING-HANDOVER-ADMIT` catalogue operation. A preparation grant cannot substitute for this permission. Catalogue registration does not extend retained assignments, authority envelopes or installation ceilings; persistent installations must qualify their explicit governed permission transition.

The review document binds every replaced trust preimage, fresh public key and reference, permitted profile and affected selection. Receipt and authority-envelope purposes remain distinct. The validity policy starts each new grant at its fenced atomic admission time and ends it at the earlier of key or credential expiry. It does not backdate new trust to preparation or copy an expired key's validity.

Candidate and approval expiry are bounded by the original possession deadline. Exact staging replay returns the original document and state, including an expired original. Changed input under the same key conflicts. A refreshed settled proof generation requires its own explicit candidate and review; it does not extend or replace the earlier approval.

The native journey checks:

- Concurrent creation retains one candidate; exact replay and restart return its original bytes.
- A preparation-only context and foreign institutional scope cannot stage the candidate.
- An incomplete direct insert through the actual runtime role fails without another candidate or signing grant.
- Maker and distinct checker use their actual synthetic authenticators and the normal approval owner. The authenticated approval record links the decision to the exact candidate digest; signed step-up evidence records authenticator verification. The candidate remains unconsumed.
- A later valid but conflicting provider response blocks a new checker decision. The earlier decision remains historical evidence; approval is not cached signing readiness.
- Signing-key grants and all original selections remain unchanged throughout these checks.

The existing catalogue oracle also compares the staging and approval predicates with the generated PostgreSQL constraint, including mismatched handover actions, catalogue operations, resource types and operation classes. Its optional port argument selects the owned isolated test database; the standard upgrade invocation retains its default port.

Candidate approval is one prerequisite for admission. The independently authenticated first admission evidence, atomic trust and selection changes, matching running consumers, signed business continuity, populated upgrades and complete forward recovery require their own connected qualification before a live transition.

## Synthetic profile receipts

The [profile receipt tests](../../tests/recovery/profile-authentication.test.mjs) generate temporary profiles, registries and P-256 signing keys. Private keys remain in the test process; the tests write only synthetic profile data, public keys and signatures to a temporary directory. No retained environment or signing-key setup is required.

The suite checks exact profile paths and purposes, registry versions, receipt digests and signatures, local proof limits, recovery mechanisms and required collections. It includes correctly signed invalid profiles so that a signature alone cannot satisfy the profile's structural requirements. The [package check](../../tests/recovery/profile-authentication-package.test.mjs) runs these cases from an isolated copy containing only the verifier and its synthetic fixtures.

Run the focused checks with the pinned Node.js version:

```sh
node --test tests/recovery/profile-authentication.test.mjs \
  tests/recovery/profile-authentication-package.test.mjs
```

These checks run through `test:unit`. They verify local test-profile admission; they do not establish deployment trust, successful database recovery or production qualification. Test a real restore through its supported operation and durable readback separately.

## Browser review

Use the actual application and authenticated workflow. Record the selected organization and actor before submitting a change. Verify dialogs, focus movement, error placement, long identifiers and stale-data removal after context changes.

A screenshot of a mock layout is design evidence, not acceptance of an authenticated journey. An API-only test cannot establish keyboard interaction or rendered reflow. Keep those evidence types distinct.

### Verify the rendered theme

Select each supported theme through the application's actual preference workflow and verify the rendered result before recording a theme check. Record the selected preference, effective theme and viewport with the screenshot or accessibility result. Browser color-scheme emulation alone does not prove that an application with an explicit theme changed its rendered palette. If the selected revision has no usable theme-selection path, report that gap rather than counting two scans of the same rendered theme as light and dark coverage.

Check text, status colors, disabled controls, errors, tables, dialogs and focus indicators in each effective theme. Include long labels and identifiers at a narrow viewport. Combine an accessibility scan with keyboard operation and visual inspection; an automated scan alone does not establish readable content or a usable task.

## Failure handling and reporting

Classify a failure as product behavior, test expectation, missing setup, resource admission, external dependency or observation failure before retrying. Restore an omitted test fixture instead of changing production code to satisfy an incomplete temporary checkout.

Retain first-failure logs privately. After possible durable effects, reconcile the same operation and environment. Do not reseed business outcomes to manufacture a pass.

In a pull request, state the exact revision, commands/scenarios, passing results, failures and unrun checks. Test counts can summarize execution, but explain the behaviors those tests cover. See the [validation plan](../evaluation/README.md) for release-level evidence.

## CI runner capacity

The CI workflow accepts an approved runner label through the repository variable
`TEGARIS_CI_RUNNER`. Use an ephemeral hosted runner for untrusted contributions;
keep production systems and persistent internal runners outside that execution
boundary.

The lightweight runner-configuration job runs on a standard hosted runner and
fails with setup guidance when `TEGARIS_CI_RUNNER` is unset or blank. Both heavy
jobs depend on that check, so they do not start dependency installation on an
undersized fallback runner. A configured label still needs a successful full run
to establish capacity and access.

Require **Required runner configuration** in branch protection alongside the
quality and runtime-integration checks. A failed prerequisite skips dependent
jobs; those skipped jobs alone must not satisfy the merge policy. See
[GitHub job conditions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-jobs-with-conditions).
Adding the workflow does not change branch-protection settings.

The workflow retains the bounded runner's memory and disk admission checks. A
40 GiB estimated build peak plus the 50 GiB disk reserve requires at least 90 GiB
free at admission, before accounting for other retained workloads. Provision
additional space for checkout, dependencies and images. A practical starting
allocation is 32 GiB RAM with at least 150 GiB free disk, subject to the actual
phase and workload inventory.

GitHub documents 14 GB of storage for its standard Ubuntu runners in the
[hosted runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
The default `ubuntu-24.04` label therefore does not establish sufficient capacity
for these declared profiles. Configure an approved larger runner and verify a
complete workflow run before treating CI as operational. Runner provisioning,
repository variables and any associated spending require the repository owner's
configuration; the workflow file alone does not provision them.

The recommended public CI target is a GitHub-hosted larger runner using Ubuntu
24.04 and x64 architecture, with 8 vCPUs, 32 GB RAM and 300 GB SSD storage. GitHub
lists this size in its [larger runner specifications](https://docs.github.com/en/actions/reference/runners/larger-runners).
The larger machine provides capacity; the repository's two-job Cargo limit and
bounded execution profiles still control individual workloads.

A repository administrator can configure the target as follows:

1. Confirm the organization's GitHub plan supports larger runners and approve its
   compute budget. Larger runners incur charges for public repositories too;
   consult [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
2. Create the runner with the image, architecture and size above. Use
   `tegaris-linux-32gb` as its name and label, or record the actual assigned label.
3. Restrict its runner group to the intended repository. Start with a maximum of
   two concurrent jobs, matching the workflow's two jobs. Keep the runner outside
   private networks and supply no deployment credentials to pull-request jobs.
4. Set the repository Actions variable `TEGARIS_CI_RUNNER` to the actual label.
   Review approval requirements for external contributions before enabling runs.
5. Run the complete workflow, confirm resource admission and inspect both job
   results. Record elapsed time and compute usage before changing capacity or
   concurrency. A queued job or successful setup step does not qualify the suite.

The prepared workflow does not provision a runner or enable billing. Until these
steps are completed, hosted CI capacity remains unverified.
