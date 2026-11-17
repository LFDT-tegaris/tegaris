# Local Compose development environment

Start with the [setup guide](../../../docs/getting-started.md) and its supported command helper. Use `run` for an automated journey or `qa-start` for a retained manual workspace. Their lifecycle and evidence are different; a stopped diagnostic environment is not a persistent manual server.

This Compose project connects Envoy, the
Next.js/Tailwind admin web BFF, the PostgreSQL-backed identity kernel, and the Rust
`FactStore`. It is a local development and test environment. Production identity, signing, provider qualification and operational readiness require separate evidence for the selected deployment. See [release scope](../../../docs/releases/README.md).

The three PostgreSQL services use explicit bind directories beneath `OPENPC_LOCAL_DATA_ROOT`.
The disposable E2E runner owns and removes only its validated external root; ordinary `down` never
deletes user data. PostgreSQL becomes healthy only after PID 1 is the final server and an
authenticated query returns the exact configured database; the temporary bootstrap postmaster
cannot admit migration jobs. One-shot migration owners apply the existing
generated identity and policy SQL, the SQLx-owned fact SQL, and the SQLx-owned candidate-index SQL.
Each applied source hash is retained in a local migration ledger; a changed previously-applied
source fails closed. The policy bootstrap uses the migration adapter that removes
only its duplicate `CREATE SCHEMA control` line in the execution stream; generated SQL bytes remain
unchanged. Candidate-index remains migrated and healthy but is not part of the selected browser
flow. Valkey and Kubernetes are absent because this flow has no consumer for either.

## Build and start

Run the supported local acceptance entrypoint from the repository root. It creates an isolated
project and fresh synthetic credentials outside the checkout, verifies the pinned toolchain,
builds with the dedicated bounded builder, stops that builder, and starts the selected services:

```sh
OPENPC_LOCAL_RUNTIME_TMP_ROOT=/absolute/path/to/private/openpc-scratch \
  bash scripts/maintenance/run-bounded.sh --profile runtime -- \
  bash tests/integration/local-runtime/run-compose-e2e.sh
```

For the governed transaction/browser slice, add
`OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER=1` before `bash` and use `--profile runtime-target`.
This runs acceptance and cleans up afterward; it is not an unattended installation command.
`OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1` retains the owned environment **stopped**, with its
project, root and ownership marker reported by the runner. Failed runs can instead be retained
with `OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE=1`. Preserve their original outcomes when diagnosing.

Compose runs migrations and initial-trust setup before application readiness. The runner owns
the complete secret/key/certificate and external-adapter configuration; the non-secret
[`.env.example`](.env.example) is a reference, not a complete bootstrap. Direct Compose commands
do not establish resource admission, builder ownership or source/image provenance.
Use the runner for new execution, and verify ownership/configuration before resuming
a retained diagnostic environment. Human transaction access uses OIDC and WebAuthn through the
Workbench. The [administration CLI](../../../apps/admin-cli/README.md) is preserved as
an experimental development interface excluded from initial-release runtime image contexts and default acceptance. Its explicit runtime checks add `OPENPC_R11_CLI=1`; ordinary transaction and CIGL browser runs do not dispatch CLI phases.

## Retained local envelope-signing provider

The local external provider adapter supports normal purpose371 signing and the exact
recovery rotation protocol over the installed mutually authenticated TLS connection.
Build a separate bundle with `pnpm --filter @openpc/identity-service
build:local-signing-provider --outfile=/absolute/path/to/private/provider-recovery.mjs`,
then select it through `OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE` in the owned Compose
configuration. Admit the build and retained runtime through the bounded runner first.
Preserve the previous bundle, provider state, installed certificates and private keys.

`OPENPC_SIGNING_PROVIDER_STATE_ROOT` and optional
`OPENPC_SIGNING_PROVIDER_SECRET_ROOT` must be absolute paths. The adapter retains
the installed business/qualification client configuration; it neither creates control
authority nor renews expired keys. Newly prepared envelope keys have an independently
bounded validity of 900–86400 seconds, selected through
`OPENPC_SIGNING_PROVIDER_ENVELOPE_KEY_VALIDITY_SECONDS` (default 86400). This does
not change the recovery Case lease or possession challenge limits.

Rotation attempts are durably recorded before private effects. Exact original lookup
reconciles provable publication or retirement; an unprovable effect stays `UNKNOWN`
and cannot be replayed. Revocation fences normal signing before private retirement,
and cold startup never reads or restores the retired predecessor's private key.
These local external-system checks do not establish a governed recovery journey or
production provider qualification.

## Health, flows, and logs

```sh
docker compose -p "$OPENPC_PROJECT" -f deploy/compose/local/compose.yaml ps
curl --fail http://127.0.0.1:9901/ready
curl --fail http://127.0.0.1:8080/api/v1/ui/local-session
docker compose -p "$OPENPC_PROJECT" -f deploy/compose/local/compose.yaml logs --no-color envoy admin-web identity-service fact-service
```

Set `OPENPC_PROJECT` to the exact owned project reported by the runner and retain that run's
configuration when inspecting it. Envoy readiness is transport health; an authenticated owner
read and the actual business outcome establish feature readiness. Never print secret files.

The selected automated flow is `tests/integration/local-runtime/run-compose-e2e.sh`. It generates
fresh external credentials, builds and starts the stack, includes checks for login/read/mutate/readback,
non-disclosing viewer denial, upstream failure translation, route rejection, restart persistence,
non-root/read-only execution, least-privilege fact-store access, image minimization, Envoy
readiness and secret-free logs, then removes containers, bind data, and temporary secrets.
Cleanup requires an unpredictable ownership sentinel and a closed run-root layout, then uses the
same digest-pinned PostgreSQL image to delete root-owned database bytes from only that validated
external mount. A missing or changed sentinel, symlink, path drift, or unknown top-level entry
fails closed.

## Stop and reset

For the retained manual workspace, stop through its identity-checked lifecycle helper:

```sh
bash scripts/operations/policy-testing.sh qa-stop --data-dir "$HOME/tegaris-dev"
```

Use the original data directory. Resume with `qa-start --local-qa-fixture` and that same directory; do not initialize over populated state. See [operations and recovery](../../../docs/operations/README.md).

For an independently owned Compose test environment, after restoring its exact project and run configuration, stop without deleting state:

```sh
docker compose -p "$OPENPC_PROJECT" -f deploy/compose/local/compose.yaml down
```

Reset is deliberately separate: after the environment has stopped, remove only the exact directory configured by
`OPENPC_LOCAL_DATA_ROOT` after verifying it is the intended local-development data root. No
repository command automatically deletes persistent data or invokes `down -v`.

## Predecessor compatibility and recovery

The local host entrypoint `scripts/operations/runtime-source-predecessor.mjs` supports the
baseline source revision pinned in the [source selector](../../../scripts/operations/runtime-source-predecessor.mjs). That revision must be available in the checkout; an export without the baseline cannot run this compatibility check. Public baseline distribution remains a release-preparation requirement. Enrollment must occur before that
predecessor's first use, against its installed schema and a new local scope/login. The entrypoint
builds the authenticated commit itself. An arbitrary old binary, an already-used unenrolled
installation, or an already-rooted scope cannot acquire this profile retroactively.

Run each phase through the existing resource owner, from the canonical repository. Set the
external envelope to cover the PostgreSQL service and all retained resources; admission refuses
an insufficient envelope. Enrollment needs eight GiB of host memory; other phases need three.

```sh
OPENPC_LOCAL_RUNTIME=1 \
  bash scripts/maintenance/run-project.sh --profile database --memory-gib 3 \
  --external-memory-gib "${OPENPC_PREDECESSOR_EXTERNAL_MEMORY_GIB:-1.25}" --peak-disk-gib 40 -- \
  node --import tsx scripts/operations/runtime-source-predecessor.mjs \
  --action status --config /absolute/private/predecessor-status.json
```

Each action uses an owned mode-0600 JSON file with no symlink/alias. Common fields are
`participantId`, `privacyDomainId` (UUIDv7), and `database` containing `host` (`127.0.0.1` or `::1`),
`port`, `name`, `user`, and an absolute `passwordFile`. The password file has the same ownership
and privacy requirements. These are synthetic local installation credentials, never production
credentials or customer data. Passwords do not appear in command arguments or status output.

| Action      | Additional config fields and effect                                                                                                                                                                                                                                                                                                            |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enroll`    | `repository` (canonical checkout), `installationId`, `legacyRole`, `workerPasswordFile`, `displayName`, `domainName`, `residencyProfile: "LOCAL_DEVELOPMENT"`. Uses the eight-GiB envelope; creates prospective cluster enrollment and initial scope. Preserve the returned executable/source references.                                      |
| `run`       | `executable`, `passwordFile`, `environmentFile`, `runId`, `logFile`. The private environment JSON contains only `CONTROL_WORKER_*` strings and file references, no inline password/secret/token. Runs the enrolled executable and records its actual exit; SIGTERM/SIGINT stops that child. A lost owner remains `RUNNING` and blocks capture. |
| `quiesce`   | No additional fields. After observed stop, closes login and database admission before checking for other sessions. A refusal preserves that fence.                                                                                                                                                                                             |
| `capture`   | `backupFile`, `captureFile`, `nativeFiles` (explicit absolute inventory). Supply the original stopped-database backup from the local backup owner after quiescence. Creates the exclusive, fsynced capture; it does not claim historical non-use or inventory completeness.                                                                    |
| `reconcile` | `captureFile`. Reconciles only the original durable capture after an interrupted completion; changed or missing bytes remain rejected.                                                                                                                                                                                                         |
| `consume`   | `captureFile`. After the existing `migrate.sh control-schema` owner completes, consumes that capture once and admits the original login only in its enrolled scope.                                                                                                                                                                            |
| `status`    | No additional fields. Reads the independent installation marker.                                                                                                                                                                                                                                                                               |

Keep the original archive, capture, keys, and business state through every failure. A consumed
capture cannot be replayed or re-enrolled. The cluster marker survives a per-database restore;
a current native worker rejects a restored predecessor schema. Supported `control-schema`
recovery recognizes only authenticated PostgreSQL dump/restore forms of the eight historical
Notification CHECK declarations, validates all prerequisites, and restores their original
expressions atomically with the unchanged schema guard. `control-restore-checks` performs the
same guarded reconciliation when no migration is pending; an unknown/modified schema fails.

Successful compatibility remains `LEGACY_UNPROVEN`. It creates no runtime-artifact source root,
non-use proof, or retirement authority, and does not qualify cluster-global restore or production
installation. This host installation/recovery entrypoint is separate from the experimental administration CLI.

The host recovery installer requires a login without superuser or RLS-bypass privileges
and explicit membership in `openpc_control_owner`. Its opt-in
`--provision-installation-login --bootstrap-database-url-file /private/bootstrap.url`
path provisions the separately supplied `--database-url-file` login
`openpc_recovery_installation` on that same database, before running the requested
installation. Both URL files must be private, owned files. Existing unknown or
modified logins are rejected; existing passwords are never reset. Bootstrap only
creates the marked login, owner membership and a direct CONNECT grant on the
selected database (the login does not inherit that grant). It creates no custody enrollment,
RecoveryCase, business approval or permission effect; those retain their separate
installation and authenticated public owners.

Recovery custody and newly proposed administrator scopes use `IDENTITY_RECOVERY_LEASE_TTL_MS`
and `IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS`. Normal limits remain 900000 ms and 3600000 ms.
Longer values require `OPENPC_LOCAL_RUNTIME_QA_FIXTURE=1` in Identity, Participant and Control API;
local QA ceilings are 3600000 ms and 86400000 ms. Startup validates the settings and records only
safe lifetime diagnostics. Each new immutable intent carries its selected lifetime profile.
The generated database window constraint, case guard and current-envelope selection enforce
that profile independently. Removing the QA flag prevents QA custody selection and execution.
Existing case, candidate, preparation, approval and certificate deadlines are never rewritten by
configuration changes; renew or supersede through their supported public owners with fresh proofs.
