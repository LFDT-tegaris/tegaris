# Control database baseline v1

**Draft: full setup and demo checks are still required before merge.** Native
PostgreSQL checks cover baseline installation, current handoff, a populated
predecessor upgrade, database backup/restore, runtime role contracts, rejected
inputs, rollback, concurrency, isolation and drift detection. They do not
establish full-stack demo or deployment readiness. The compact checkout has a
separate fresh setup and governed-RPC CI step; passing historical tests in the
legacy source view cannot clear that gate.

This baseline freezes the public source at `db5e64b566712e5213424db5e166775d9a15a7be`.
The current baseline tests target PostgreSQL 18.6, pgcrypto 1.4, UTF-8, and database
`openpc_control`. Fact and candidate-index SQLx histories are unchanged.

The ordinary `deploy/compose/local/migrate.sh` entrypoint uses the compact
baseline for an empty database. A current legacy database must match the complete
catalogue, required public action catalogue, and all 470 original control-store
migration checksums before a separate handoff receipt is recorded. Its historical
receipts and application rows are retained. A fresh baseline does not claim to
have executed those historical migrations.

Two exact catalogue profiles preserve the immutable legacy runner's installation
paths. An older owner-created `openpc.reject_policy_immutable_mutation()` trigger
can retain a private ACL; the clean legacy path retains PUBLIC EXECUTE on that
same trigger. The baseline does not reconcile those permissions. Handoff records
the accepted profile and its catalogue fingerprint. Verification and restore then
require that profile, including every grant bit; changing between even these two
recognized profiles is rejected. A fresh baseline always uses the canonical
profile. Unknown variants still fail closed.

Unknown schemas, incomplete or altered legacy histories, unexpected role
privileges, and unsupported PostgreSQL versions stop before installation changes.
An older database needs an explicit upgrade through the verified compatibility
package first. Installing or upgrading an existing environment is a separate
operator action; this repository change does not deploy anything.

## Runtime role lifecycle

Runtime-source installation creates scoped marker/login roles after database
setup; an optional archive has its own login. These identities vary by workspace
and cannot be part of the frozen schema fingerprint. Before projecting them out,
the verifier checks their exact reserved name format, scope-name derivation,
installation/root binding shape, paired identities and archive profile. A v2
materialization binding must still name the current database and cluster.

These roles must retain the installer-created attributes and memberships: no
superuser, role/database creation, replication, RLS bypass, role settings, direct
object ownership or ACL/policy privileges, including outside the frozen schemas.
Source and archive logins inherit only `openpc_control_worker`; a source login
also has its own marker membership with ADMIN, INHERIT and SET disabled. Grantors
must be superusers and no other consumer can inherit a source or marker identity.
All static catalogue fields, grants, grant options, ownership and RLS checks stay
exact. Unrecognized role layouts remain rejected. The verifier never creates,
repairs or reenrolls runtime identities, copies passwords or rewrites bindings.

This is a migration compatibility check, not custody authentication. The Rust
source installer/authenticator remains responsible for actual keys, retained
files, journals, scope authority and consumer startup. Synthetic SQL role probes
cannot substitute for the fresh runtime and demo checks below.

## Offline compatibility package

The versioned `legacy-package.json` identifies the original source, every file,
and the compressed archive SHA-256. The archive contains the original migration
files, snapshots, journals, runner, and license. It is distributed separately;
placing it back inside the source tree would defeat the checkout reduction.

The package can be reproduced from the pinned Git history before a versioned
release asset is available. Keep the output filename shown here and write the
reproduced manifest outside the checkout; verification uses the repository's
trusted manifest.

```sh
python3 scripts/migrations/compatibility.py build \
  --output /path/to/tegaris-legacy-db-db5e64b.tar.gz \
  --manifest /path/to/reproduced-legacy-package.json
```

```sh
python3 scripts/migrations/compatibility.py verify \
  --archive /path/to/tegaris-legacy-db-db5e64b.tar.gz \
  --destination /path/to/new/verified-legacy-source
```

No download or database action occurs during verification. Extraction rejects
unexpected, missing, duplicate, absolute, traversal, and link entries. Files are
exposed at the destination only after the entire package verifies.

For an approved older-installation upgrade, use the unchanged runner and migration
tree from that package, with the original `/migrations/postgres` mount paths.
After its successful upgrade, the ordinary current entrypoint can verify and
record the handoff. Never edit applied SQL or manufacture historical receipts.

Keep a database backup and the previous release before an installation upgrade.
Switching source revisions does not downgrade a database. A fresh baseline has
no historical migration receipts, so the legacy installer must not replay its
history over that database. Recovery uses a compatible backup and the qualified
restore path into a new, empty target. This change provides no automatic schema
downgrade.

## Generation and future database changes

The latest Drizzle snapshot, original journal, and latest SQL anchor remain in
each lane. Identity and Policy security projections need older DDL to derive and
verify their guards, so these commands read authenticated historical inputs from
an explicit offline cache:

```sh
export OPENPC_LEGACY_SOURCE_ROOT=/path/to/new/verified-legacy-source
cd services/identity-service
pnpm run db:generate
```

Use the same cache for Policy migration generation or standalone security checks:

```sh
OPENPC_LEGACY_SOURCE_ROOT=/path/to/new/verified-legacy-source \
  node services/module-registry/src/db/verify-policy-security.mjs
```

Run that check from the repository root. Normal image builds and empty-database
baseline installation do not require this development cache.

The cache is read only. Historical files are never materialized into the default
checkout and every historical input used by generation is checked against its
source checksum.

This change preserves the existing complete security-projection generator. It
does not introduce delta-only guard generation. The 25 MB migration budget and
the frozen v1 SQL-anchor check prevent unbounded history or an unregistered
migration from silently entering an installer that would ignore it. A subsequent
database change must include a qualified incremental installation path or a new
versioned baseline, with the same upgrade and restore validations.

## Backup restore

These candidate commands do not yet establish recovery of a fully bootstrapped
demo workspace. The setup and demo merge gates below remain required.

Use a new, empty target with the original initdb bootstrap account name. The
restore path provisions the pinned pgcrypto extension under its correct owner;
ordinary pg_restore does not preserve that extension owner. Database ACLs are
also prepared explicitly because a restore without `--create` omits them.

A database dump does not contain cluster roles. A source-bearing restore must
retain the original scope/login bindings; missing roles are rejected rather than
recreated from database rows. The native v1 restore test retains those roles in
the same disposable cluster. A v2 materialization binding also pins the database
OID and cluster identifier: moving it to a different database or cluster is
rejected. This tool does not restore cluster globals or custody files. Keep the
original keys, retained files and journals; their recovery and consumer startup
still need independent qualification.

Set `PGHOST`, `PGPORT`, `PGUSER`, and `PGDATABASE=openpc_control` for that target:

```sh
python3 scripts/migrations/restore.py \
  --archive /path/to/control.dump --sha256 TRUSTED_BACKUP_SHA256
```

The target must be empty. The tool does not drop databases, overwrite existing
application objects, or start services. It restores the archive in one
transaction, excluding only the pre-provisioned pgcrypto CREATE EXTENSION entry.
It then accepts only the original catalogue or the independently derived
PostgreSQL 18.6 dump/reparse profile. Exact authenticated CHECK and policy source
forms are restored atomically and the full catalogue and seed checks run again.
An unknown difference is an error, not an allowed normalization.

Keep the restored installation offline until this command succeeds. On failure,
retain the isolated target and logs for investigation.

## Validation and reproducibility

The separate `Migration readiness` workflow runs dependency-free synthetic setup,
sign-in, RPC evidence and recovery contract checks on a disposable Linux runner.
It also checks available capacity before scheduling the native database proof;
the proof rechecks admission on its own runner and retains the 50 GiB reserve.
Insufficient capacity skips that proof explicitly. A portable pass or capacity
probe does not clear full setup, custody, demo or the separately required `ci`
workflow. Those heavy jobs still require the configured larger runner.

The focused `run-linux-custody.sh` gate uses the actual source installer and Rust
source/archive recovery tests against the compact baseline. It refuses a legacy
or rehydrated checkout before allocation. The readiness workflow attempts it only
when measured capacity permits; the heavy runtime workflow also requires it
before the historical test view. Its component result cannot qualify the full
setup or browser/demo journey.

Only the standalone custody job may reclaim unused .NET/Android SDK space in
its own fresh GitHub-hosted Linux VM. It rejects other execution environments
before removal and rechecks free space afterward; the normal workload admission
still enforces the memory budget and 50 GiB reserve. Existing installations and
persistent runners are outside this preparation.

```sh
node --version # Use the exact package.json pin.
bash scripts/migrations/run-portable-readiness.sh
python3 -m unittest discover -s tests/migration -p 'test_*.py'
node --test --test-concurrency=1 tests/migration/legacy-inputs.test.mjs tests/migration/policy-readiness.test.mjs tests/migration/setup-gate.test.mjs
python3 scripts/migrations/check-size.py
python3 tests/migration/run-baseline-proof.py \
  --pg-bin /path/to/postgresql-18.6/bin \
  --archive /path/to/tegaris-legacy-db-db5e64b.tar.gz \
  --work-dir /tmp/new-tegaris-baseline-proof
```

The PostgreSQL proof requires matching pgcrypto binaries. It creates its own
Unix-socket-only clusters, preserves synthetic logs/backups, and stops only its
own servers. It exercises both `postgres` and the Compose bootstrap account
`openpc_control`. Bootstrap OID 10 is represented portably in catalogue comparisons;
other role identities, grants, grant options, ownership, policies and definitions
remain exact.

## Setup and demo merge gates

Qualification must use the actual compact checkout at the proposed merge commit,
including the baseline installer. The following checks remain required:

- Follow `docs/getting-started.md` in a new isolated Linux workspace: prerequisite
  checks, locked dependencies and all seven service-image builds, including the
  console and Rust helpers.
- Start the documented synthetic QA workspace, confirm completed migrations and
  healthy services, and complete sign-in with its own fixture accounts.
- Exercise normal runtime-source and archive installation, repeated migration,
  stop/resume and restart without changing established credentials, keys, receipt
  identities or business data. Use the actual source installer, not SQL fixtures.
- Run initial policy setup, independent review, activation, permitted and denied
  governed requests, and the corresponding public readback and browser checks.
- Validate supported upgrade and backup/recovery paths on populated disposable
  workspaces; unsupported custody/cluster restoration must stay rejected.
- Preserve the existing demo's documented coverage and limits. Reproducing the
  hosted reference examples requires their synthetic contract fixtures and
  matching deployment bindings; local startup does not import them automatically.
- Pass the fresh compact-checkout gate and the separate historical/full CI suites.

No merge or release is qualified by source equivalence, a successful database
install, an image bundle, or a documentation check alone. Existing installations
and the hosted demo are outside these disposable validation runs.

Historical tests run current implementation code in a separate source view with
SQL from the immutable public commit. They never rehydrate the default checkout.
For individual historical suites, use the same explicit wrapper:

```sh
python3 scripts/migrations/legacy-test-view.py \
  --directory /tmp/new-tegaris-historical-view \
  --command pnpm run test:integration:runtime
```

CI fetches that history explicitly for these tests and separately builds pinned
PostgreSQL 18.6 to run the compact baseline proof on Linux. The CI build needs
the compiler, Bison, Flex, OpenSSL and zlib development packages; it installs
PostgreSQL only under its new external scratch directory and starts no system
service. `scripts/migrations/run-linux-proof.sh` also reproduces the compatibility
archive against the repository's pinned manifest without rewriting it.

Git history is retained. The size reduction refers to tracked checkout/source-archive bytes, not a promise
of equivalent full-clone savings.
