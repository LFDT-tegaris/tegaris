import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID, X509Certificate } from 'node:crypto';
import { lstatSync, realpathSync, statfsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { isAbsolute, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { Client, Pool } from 'pg';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { verifyInstalledSecretRecipient } from '../../../packages/security-kernel/src/secret-recipient/profile.ts';
import { createTestFactSecretConsumer } from '../../../scripts/operations/test-fact-secret-consumer.mjs';
import { parseConfigurationJson } from '../../../scripts/operations/installation-config-inputs.mjs';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import {
  createFactSecretPublishGate,
  assertFactSecretOperationsOwner,
} from './fact-secret-operations.mjs';

const binary = '/usr/local/bin/openpc-fact-local-runtime';
const configurationPath = '/fact-bridge/deployment.json';
const recipientPath = '/fact-bridge/secret-recipient.json';
const mountPath = '/fact-bridge/candidate-url';
const role = 'openpc_fact_bridge_reader';
const nodeImage =
  'docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43';
// This executes only inside an exclusively owned Fact container. A vanished,
// reaped/reused or zombie PID is not running; an unreadable identity is UNKNOWN.
const stopFactProcess = `
pid=$1; started=$2; executable=$3
same_live_process() {
  [ -e "/proc/$pid/stat" ] || return 1
  observed=$(awk '{print $3 " " $22}' "/proc/$pid/stat") || {
    [ ! -e "/proc/$pid/stat" ] && return 1
    return 2
  }
  [ "\${observed#* }" = "$started" ] || return 1
  [ "\${observed%% *}" != Z ] || return 1
}
same_live_process; status=$?
[ "$status" != 1 ] || exit 0
[ "$status" = 0 ] || exit 96
test "$(readlink "/proc/$pid/exe")" = "$executable" || exit 96
kill -TERM "$pid" || {
  same_live_process; status=$?
  [ "$status" = 1 ] && exit 0
  exit 96
}
count=0
while :; do
  same_live_process; status=$?
  [ "$status" != 1 ] || exit 0
  [ "$status" = 0 ] || exit 96
  count=$((count+1)); [ "$count" -lt 100 ] || exit 96
  sleep 0.05
done
`;
const causes = new WeakMap();
const emit = (status, phase) => {
  try {
    process.stdout.write(`FACT_SECRET_CONSUMER_JOURNEY|${status}|${phase}\n`);
  } catch {
    // Diagnostic failure cannot replace the original failure or skip cleanup.
  }
};
const sameInode = (a, b) => a.device === b.device && a.inode === b.inode;
const decodeMount = (value) =>
  value.replace(/\\([0-7]{3})/gu, (_, octal) => String.fromCharCode(parseInt(octal, 8)));
async function wait(predicate, timeout = 10000) {
  const end = performance.now() + timeout;
  while (!(await predicate())) {
    if (performance.now() >= end) throw new Error('Bounded Fact observation did not complete');
    await delay(25);
  }
}

// Assertions/native failures can contain credentials. Keep the original cause
// private; every subsequent stage/close rethrows the SAME first redacted error,
// including when the initial rejection is undefined. No raw cause is logged.
function failureOwner() {
  let failure;
  return {
    capture(error, phase) {
      if (!failure) {
        failure = new Error('Packaged Fact secret journey failed');
        causes.set(failure, error);
        emit('FAIL', phase);
        try {
          // Only an owned source line is public. Never emit assertion values,
          // SQL text, response bodies, paths or the original error message.
          const line = /fact-secret-consumer-journey\.mjs:([1-9][0-9]{0,5}):[0-9]+/u.exec(
            typeof error?.stack === 'string' ? error.stack : '',
          );
          if (line) emit('LOCATION', `journey-line-${line[1]}`);
        } catch {
          // Diagnostic access cannot replace the original failure.
        }
      }
      return failure;
    },
    assertHealthy() {
      if (failure) throw failure;
    },
  };
}

function borrowedPool(pool) {
  assert.ok(pool instanceof Pool);
  // A pool checkout or failed database must not hold a stage/cleanup forever.
  // These are actual pg construction options, never readiness assertions.
  assert.ok(
    pool.options.connectionTimeoutMillis > 0 && pool.options.connectionTimeoutMillis <= 5000,
  );
  assert.ok(pool.options.query_timeout > 0 && pool.options.query_timeout <= 10000);
}

/** Read-only preflight for the installer's exclusively owned, dedicated slice.
 * Global emptiness comes from the existing installation account's unfiltered
 * base-table reads, never from an RLS-filtered admission view. The caller also
 * owns the live Docker topology/resource guard; a database snapshot cannot grant
 * exclusive fixture ownership or prevent a future external writer from starting.
 * This does not reserve/activate the reader lease or admit any business effect.
 */
export async function assertEmptyFactCandidateSlice(pool, scope) {
  borrowedPool(pool);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  const { participantId, privacyDomainId } = scope;
  assert.match(participantId, uuid);
  assert.match(privacyDomainId, uuid);
  const operation = localOperationId();
  const client = await pool.connect();
  let connectionErrors = 0;
  let outcome = { failed: false };
  const failed = (error) => {
    if (!outcome.failed) outcome = { failed: true, error };
  };
  const unknown = (phase) => {
    try {
      emit('UNKNOWN', phase);
    } catch {
      // Diagnostic failure cannot replace the first error or skip release.
    }
  };
  client.on('error', (error) => {
    connectionErrors++;
    failed(error);
  });
  const query = async (...args) => {
    if (outcome.failed) throw outcome.error;
    const result = await client.query(...args);
    if (outcome.failed) throw outcome.error;
    return result;
  };
  async function noWriters() {
    await query('select pg_stat_clear_snapshot()');
    const { rows } = await query(`select
      exists(select 1 from pg_stat_activity a
        where a.datname=current_database() and a.pid<>pg_backend_pid() and (
          a.backend_type='logical replication worker' or
          (a.backend_type='client backend' and (
            a.usename is distinct from 'openpc_candidate_index' or
            a.state like 'idle in transaction%' or
            (a.state='active' and a.query !~* '^[[:space:]]*select[[:space:]]+1[[:space:]]*;?[[:space:]]*$'))))) sessions,
      exists(select 1 from pg_locks l join pg_class c on c.oid=l.relation
        join pg_namespace n on n.oid=c.relnamespace
        where l.database=(select oid from pg_database where datname=current_database())
          and n.nspname='candidate' and l.pid is distinct from pg_backend_pid()
          and l.mode<>'AccessShareLock') writers,
      exists(select 1 from pg_prepared_xacts where database=current_database()) prepared`);
    assert.deepEqual(rows, [{ sessions: false, writers: false, prepared: false }]);
  }
  try {
    await query('begin isolation level repeatable read read only');
    await query("set local statement_timeout='5s'");
    await query("set local lock_timeout='2s'");
    const identity = await query(`select current_database() name,current_user role,
      session_user session,r.rolsuper,r.rolbypassrls,pg_get_userbyid(d.datdba) owner
      from pg_roles r cross join pg_database d
      where r.rolname=current_user and d.datname=current_database()`);
    assert.equal(identity.rowCount, 1);
    const installedAdmin = identity.rows[0];
    assert.equal(installedAdmin.name, 'openpc_candidate_index');
    assert.equal(installedAdmin.role, 'openpc_candidate_index');
    assert.equal(installedAdmin.session, installedAdmin.role);
    assert.equal(installedAdmin.owner, 'openpc_candidate_index_owner');
    assert.ok(
      installedAdmin.rolsuper || installedAdmin.rolbypassrls,
      'Global emptiness requires the existing isolated installation account',
    );
    const owners = await query(`select rolname,rolcanlogin,rolsuper,rolbypassrls,
      rolcreaterole,rolcreatedb,rolreplication,
      exists(select 1 from pg_auth_members where member=r.oid) memberships
      from pg_roles r where rolname in ('openpc_candidate_index_owner','openpc_fact_bridge_reader')
      order by rolname`);
    assert.equal(owners.rowCount, 2);
    for (const owner of owners.rows) {
      for (const flag of [
        'rolsuper',
        'rolbypassrls',
        'rolcreaterole',
        'rolcreatedb',
        'rolreplication',
        'memberships',
      ])
        assert.equal(owner[flag], false);
      if (owner.rolname === 'openpc_candidate_index_owner') assert.equal(owner.rolcanlogin, false);
    }
    const schemas = await query(`select nspname,pg_get_userbyid(nspowner) owner
      from pg_namespace where nspname in ('candidate','openpc') order by nspname`);
    assert.deepEqual(
      schemas.rows,
      ['candidate', 'openpc'].map((nspname) => ({
        nspname,
        owner: 'openpc_candidate_index_owner',
      })),
    );
    const view = await query(`select c.relkind,pg_get_userbyid(c.relowner) owner,c.reloptions,
      has_table_privilege('openpc_fact_bridge_reader',c.oid,'SELECT') readable
      from pg_class c join pg_namespace n on n.oid=c.relnamespace
      where n.nspname='candidate' and c.relname='fact_bridge_admission_v1'`);
    assert.equal(view.rowCount, 1);
    assert.equal(view.rows[0].relkind, 'v');
    assert.equal(view.rows[0].owner, 'openpc_candidate_index_owner');
    assert.ok(view.rows[0].reloptions?.includes('security_barrier=true'));
    assert.ok(!view.rows[0].reloptions.includes('security_invoker=true'));
    assert.equal(view.rows[0].readable, true, 'Missing existing Fact admission SELECT grant');
    const tables = await query(`select c.relname,c.relkind,pg_get_userbyid(c.relowner) owner,
      c.relrowsecurity,c.relforcerowsecurity
      from pg_class c join pg_namespace n on n.oid=c.relnamespace
      where n.nspname='candidate' and c.relkind in ('r','p','f','m') order by c.relname`);
    // These are all base relations used by the owner-rights admission view.
    for (const name of [
      'outbox_event',
      'candidate_partition',
      'projection_generation',
      'projection_profile',
      'source_profile',
      'source_publication',
      'candidate_event',
      'candidate_block',
      'checkpoint',
      'candidate_invalidation',
    ]) {
      const table = tables.rows.find((row) => row.relname === name);
      assert.ok(table?.relrowsecurity && table.relforcerowsecurity);
    }
    await noWriters();
    // row_security=off alone is not a bypass. The checked installation account
    // must already possess that authority; a weaker account fails closed above.
    await query('set local row_security=off');
    for (const table of tables.rows) {
      assert.equal(table.owner, 'openpc_candidate_index_owner');
      assert.ok(['r', 'p'].includes(table.relkind));
      assert.match(table.relname, /^[a-z][a-z0-9_]*$/u);
      // Migration history and installed retirement trust may exist in a fresh
      // fixture. Every other base table (including other scopes, partial joins,
      // migration cohorts and retirement/replay records) must actually be empty.
      if (['schema_migration', 'retirement_capability_secret'].includes(table.relname)) continue;
      const occupied = await query(
        `select exists(select 1 from candidate."${table.relname}") occupied`,
      );
      assert.deepEqual(occupied.rows, [{ occupied: false }]);
    }
    await query('set local row_security=on');
    await query('set local role openpc_fact_bridge_reader');
    await query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',true)",
      [participantId, privacyDomainId, operation],
    );
    // Evaluate context even when the empty view never invokes an RLS predicate.
    // These SECURITY INVOKER calls exercise the existing transitive reader grants.
    await query('select openpc.assert_request_context(true)');
    const context = await query(
      `select current_user role,current_setting('transaction_read_only') read_only,
      current_setting('openpc.context_mode') mode,openpc.current_participant_id() participant,
      openpc.current_privacy_domain_id() privacy,openpc.current_operation_id() operation,
      openpc.current_action_intent_id() action,
      openpc.matches_participant($1::uuid) participant_match,openpc.matches_privacy($2::uuid) privacy_match`,
      [participantId, privacyDomainId],
    );
    assert.deepEqual(context.rows, [
      {
        role,
        read_only: 'on',
        mode: 'PARTICIPANT',
        participant: participantId,
        privacy: privacyDomainId,
        operation,
        action: 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',
        participant_match: true,
        privacy_match: true,
      },
    ]);
    const scoped = await query(
      'select exists(select 1 from candidate.fact_bridge_admission_v1) occupied',
    );
    assert.deepEqual(scoped.rows, [{ occupied: false }]);
    await query('set local role openpc_candidate_index');
    await noWriters();
  } catch (error) {
    failed(error);
  } finally {
    let rollbackKnown = false;
    try {
      await client.query('rollback');
      rollbackKnown = connectionErrors === 0;
    } catch (error) {
      failed(error);
    }
    if (!rollbackKnown) unknown('candidate-preflight-rollback');
    const errorsBeforeRelease = connectionErrors;
    try {
      // Never return a scoped/role-switched session to the borrowed pool, even
      // if the connection failed before BEGIN or rollback acknowledgement was lost.
      client.release(true);
      if (connectionErrors !== errorsBeforeRelease) unknown('candidate-preflight-release');
    } catch (error) {
      failed(error);
      unknown('candidate-preflight-release');
    }
  }
  if (outcome.failed) throw outcome.error;
}

function installation(input, configurationBytes, recipientBytes) {
  assert.ok(['consumer-revocation', 'consumer-expiry'].includes(input.mode));
  const configuration = parseConfigurationJson(configurationBytes);
  const recipient = parseConfigurationJson(recipientBytes, 16384);
  const installed = {
    ...input.pins,
    issuerSpkiDer: Buffer.from(input.pins.issuerSpkiDer, 'base64'),
  };
  assert.deepEqual(configuration.candidate_secret_recipient, recipient);
  assert.equal(configuration.candidate_database_url_file, mountPath);
  for (const [field, pin] of [
    ['signed_binding_digest', 'signedBindingDigest'],
    ['installation_digest', 'installationDigest'],
    ['generation', 'generation'],
    ['workload_credential_id', 'workloadCredentialId'],
    ['workload_credential_epoch', 'workloadCredentialEpoch'],
  ])
    assert.equal(recipient[field], installed[pin]);
  assert.equal(configuration.participant_id, installed.participantId);
  assert.equal(configuration.privacy_domain_id, installed.privacyDomainId);
  assert.equal(recipient.reference, input.reference);
  assert.equal(recipient.version, 'v1');
  assert.equal(recipient.endpoint.path, '/internal/v1/secrets/fact-candidate');
  assert.equal(recipient.addresses.length, 1);
  assert.ok(isIP(recipient.addresses[0]) && recipient.endpoint.port > 0);
  const tls = Object.fromEntries(
    Object.entries(input.tls.server).map(([name, value]) => [name, Buffer.from(value, 'base64')]),
  );
  assert.equal(
    sha256(new X509Certificate(tls.certificate).raw).slice(7),
    recipient.server_certificate_digest,
  );
  assert.ok(Number.isSafeInteger(input.validUntilMs));
  assert.ok(input.validUntilMs - Date.now() >= 15000, 'Insufficient fresh authority');
  if (input.mode === 'consumer-expiry') assert.ok(input.validUntilMs - Date.now() <= 120000);
  return { configuration, recipient, installed, tls };
}

/** PUBLISHER STAGE: imported by the existing installer inside its pinned Node
 * container. Both pools are real borrowed installation-owned pools. The candidate
 * pool connects to the separate store, never a rewritten Control URL. Keep this
 * handle/process alive through prepare, bind and restart; await close before
 * ending pools or removing the exclusively owned volume. No Docker access or new
 * protocol exists in this process. The existing factory alone authenticates TLS,
 * checks all seven pins, publishes and owns LOGIN/session revocation. Returning
 * this handle is not startup authority. Configuration files use the fixed paths
 * above and the publication root is an empty UID/GID65532,0700 tmpfs mount.
 */
export async function startFactSecretConsumerPublisher(
  input,
  { publicationRoot, runtimePool, candidateAdminPool },
) {
  const failures = failureOwner();
  let app, expected, closing;
  const gate = input.operations
    ? createFactSecretPublishGate(input.operations.association_id)
    : undefined;
  const close = () => {
    closing ??= (async () => {
      gate?.abort();
      try {
        await app?.close();
      } catch (error) {
        emit('UNKNOWN', 'publisher-cleanup');
        throw failures.capture(error, 'publisher-cleanup');
      } finally {
        expected?.fill(0);
      }
      failures.assertHealthy();
    })();
    return closing;
  };
  try {
    input = structuredClone(input);
    assert.equal(process.geteuid(), 65532);
    assert.equal(process.getegid(), 65532);
    borrowedPool(runtimePool);
    borrowedPool(candidateAdminPool);
    assert.ok(isAbsolute(publicationRoot) && realpathSync(publicationRoot) === publicationRoot);
    const root = lstatSync(publicationRoot);
    assert.ok(root.isDirectory());
    assert.equal(root.uid, 65532);
    assert.equal(root.gid, 65532);
    assert.equal(root.mode & 0o7777, 0o700);
    assert.equal(statfsSync(publicationRoot, { bigint: true }).type, 0x01021994n);
    const { configuration, recipient, installed, tls } = installation(
      input,
      await readFile(configurationPath),
      await readFile(recipientPath),
    );
    assert.deepEqual(
      await readFile(configuration.client_chain_der_files[0]),
      new X509Certificate(Buffer.from(input.tls.certificate, 'base64')).raw,
    );
    // Reject an occupied store/context mismatch before the factory reserves the
    // LOGIN lease. The installed scope is checked against the actual mounted input.
    await assertEmptyFactCandidateSlice(candidateAdminPool, installed);
    assert.ok(input.validUntilMs - Date.now() >= 15000, 'Insufficient fresh authority');
    expected = Buffer.from(input.material, 'base64');
    app = await createTestFactSecretConsumer({
      pool: runtimePool,
      kernel: new IdentityKernel(new PostgresIdentityRepository(runtimePool)),
      candidateAdminPool,
      installed,
      tls,
      rootPath: publicationRoot,
      reference: input.reference,
      version: 'v1',
      syntheticMaterial: expected,
    });
    if (gate)
      app.addHook('preHandler', async (request, reply) => {
        if (
          request.routeOptions.url === '/internal/v1/secrets/fact-candidate' &&
          request.body?.operation === 'PUBLISH'
        ) {
          try {
            await gate.wait();
          } catch {
            return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
          }
        }
      });
    await app.listen({ host: recipient.addresses[0], port: recipient.endpoint.port });
    expected.fill(0);
    return Object.freeze({
      close,
      ...(gate
        ? {
            descriptor: app.operationsSecretResolutionDescriptor,
            arm: (associationId) => gate.arm(associationId),
            release: (associationId) => gate.release(associationId),
            abort: () => gate.abort(),
          }
        : {}),
    });
  } catch (error) {
    const primary = failures.capture(error, 'publisher-start');
    await close().catch(() => undefined);
    throw primary;
  }
}

// Native Docker output stays private and bounded. Creation, bind mounts,
// admission and container removal remain with the existing runtime owner. These
// helpers inspect/exec exact owned IDs; there is no configurable command callback.
function dockerProcess(args, input) {
  const child = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const record = { child, bytes: 0, chunks: [], result: undefined, failed: false };
  record.done = new Promise((resolve) => {
    child.once('error', () => {
      record.failed = true;
      record.result = { code: null, signal: 'SPAWN_ERROR' };
      resolve(record.result);
    });
    child.once('close', (code, signal) => {
      record.result = { code, signal };
      resolve(record.result);
    });
  });
  for (const stream of [child.stdout, child.stderr])
    stream.on('data', (bytes) => {
      record.bytes += bytes.length;
      if (record.bytes > 262144) {
        record.failed = true;
        // A stopped Docker client is NOT proof that the remote process stopped.
        child.kill('SIGTERM');
      } else if (stream === child.stdout || args[0] === 'logs')
        record.chunks.push(Buffer.from(bytes));
    });
  child.stdin.on('error', () => {
    record.failed = true;
  });
  child.stdin.end(input);
  return record;
}
function eraseOutput(record) {
  for (const bytes of record.chunks) bytes.fill(0);
  record.chunks.length = 0;
}
async function docker(args, input) {
  const record = dockerProcess(args, input);
  try {
    await wait(() => record.result !== undefined);
    assert.equal(record.failed, false);
    assert.equal(record.result.code, 0);
    return Buffer.concat(record.chunks);
  } finally {
    if (!record.result) record.child.kill('SIGTERM');
    eraseOutput(record);
  }
}
async function nativeJson(args) {
  const bytes = await docker(args);
  try {
    return JSON.parse(bytes.toString());
  } finally {
    bytes.fill(0);
  }
}

/** Bounded diagnostic readback only. The journey first verifies its original
 * stopped container; this helper neither starts it nor grants readiness. */
export async function readFactSecretRuntimeFailure(containerId, startedAt, classification) {
  assert.match(containerId, /^[0-9a-f]{64}$/u);
  assert.ok(typeof startedAt === 'string' && Number.isFinite(Date.parse(startedAt)));
  assert.ok(
    ['fact secret recipient revoked', 'fact installed secret recipient unavailable'].includes(
      classification,
    ),
  );
  const bytes = await docker(['logs', '--since', startedAt, containerId]);
  try {
    const stopped = bytes
      .toString()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .filter((value) => value.event === 'fact_runtime_stopped');
    if (stopped.length === 0) return false;
    assert.equal(stopped.length, 1);
    assert.equal(stopped[0].level, 'error');
    assert.equal(stopped[0].classification, classification);
    return true;
  } finally {
    bytes.fill(0);
  }
}
function environment(container) {
  const result = new Map();
  for (const entry of container.Config.Env) {
    const index = entry.indexOf('=');
    assert.ok(index > 0);
    const name = entry.slice(0, index);
    assert.equal(result.has(name), false);
    result.set(name, entry.slice(index + 1));
  }
  return result;
}
const runtimeNames = [
  'OPENPC_LOCAL_RUNTIME',
  'OPENPC_FACT_BRIDGE_CONFIGURATION_FILE',
  'OPENPC_LOCAL_RUNTIME_FACT_SECRET_RECIPIENT_CONFIG',
  'OPENPC_FACT_DATABASE_HOST',
  'OPENPC_FACT_DATABASE_PORT',
  'OPENPC_FACT_DATABASE_NAME',
  'OPENPC_FACT_DATABASE_USER',
  'OPENPC_FACT_DATABASE_PASSWORD_FILE',
  'OPENPC_FACT_CAPABILITY_SECRET_FILE',
  'OPENPC_FACT_SIGNING_SECRET_FILE',
  'OPENPC_FACT_INTERNAL_TOKEN_FILE',
  'OPENPC_FACT_LISTEN',
];
const execArgs = (id, ...args) => ['exec', '--user', '65532:65532', id, ...args];
async function containerFile(id, path, limit) {
  assert.ok(isAbsolute(path) && !path.includes('\0'));
  const bytes = await docker(execArgs(id, '/bin/cat', '--', path));
  if (bytes.length > limit) {
    bytes.fill(0);
    throw new Error('Container file exceeds bound');
  }
  return bytes;
}
async function statFile(id, path) {
  const bytes = await docker(
    execArgs(id, '/usr/bin/stat', '--format=%d|%i|%u|%g|%a|%s|%h|%F', '--', path),
  );
  const [device, inode, uid, gid, mode, size, links, kind] = bytes.toString().trim().split('|');
  bytes.fill(0);
  for (const value of [device, inode, uid, gid, size, links]) assert.match(value, /^\d+$/u);
  assert.match(mode, /^[0-7]+$/u);
  assert.ok(kind === 'regular file' || kind === 'regular empty file');
  return { device, inode, uid, gid, mode, size, links };
}
// Only publisher observations use Node. Consumer observations use Debian's
// existing cat/stat/readlink and /proc, never an assumed Node installation.
async function publicationState(id, root) {
  const bytes = await docker(
    execArgs(
      id,
      'node',
      '--input-type=module',
      '-e',
      `import {lstatSync,realpathSync,statfsSync} from 'node:fs';
const root=process.argv[1],s=lstatSync(root);
if(!s.isDirectory()||s.uid!==65532||s.gid!==65532||(s.mode&4095)!==448||realpathSync(root)!==root||statfsSync(root,{bigint:true}).type!==0x01021994n)process.exit(96);
let f;try{f=lstatSync(root+'/candidate-url',{bigint:true});}catch(e){if(e.code!=='ENOENT')throw e;}
if(f&&!f.isFile())process.exit(96);
process.stdout.write(JSON.stringify(f?{device:String(f.dev),inode:String(f.ino),uid:String(f.uid),gid:String(f.gid),mode:(f.mode&4095n).toString(8),size:String(f.size),links:String(f.nlink)}:null));`,
      root,
    ),
  );
  try {
    return JSON.parse(bytes.toString());
  } finally {
    bytes.fill(0);
  }
}

export function assertFactSecretPublishedBind(current, publicationSource, publicationVolumeSource) {
  const binds = current.Mounts.filter((m) => m.Destination === mountPath);
  assert.equal(binds.length, 1);
  assert.equal(binds[0].Type, 'bind');
  assert.equal(binds[0].Source, publicationSource);
  assert.equal(binds[0].RW, false);
  // Docker volume-root sources require rslave: inbound propagation only.
  // The pinned regular file remains read-only; shared/writable binds deny.
  assert.equal(binds[0].Propagation, 'rslave');
  assert.equal(
    current.Mounts.some((m) => m.RW && m.Source === publicationVolumeSource),
    false,
  );
}

/** Docker derives Mounts from an unordered map. Compare its complete records
 * by unique destination. Docker may change the OOM default from false to null
 * on start (observed with cgroup v2); neither disables OOM killing. Reject true
 * or malformed values before canonicalizing this one default representation. */
export function factSecretContainerConfiguration(value) {
  assert.ok(value.HostConfig.OomKillDisable === false || value.HostConfig.OomKillDisable === null);
  assert.ok(Array.isArray(value.Mounts));
  const destinations = value.Mounts.map((mount) => {
    assert.equal(typeof mount.Destination, 'string');
    return mount.Destination;
  });
  assert.equal(new Set(destinations).size, destinations.length);
  return {
    config: value.Config,
    host: { ...value.HostConfig, OomKillDisable: false },
    mounts: [...value.Mounts].sort((left, right) =>
      left.Destination.localeCompare(right.Destination, 'en'),
    ),
  };
}

/** OBSERVER STAGES: imported by the existing admitted host installer.
 *
 * Inputs: borrowed controlAdminPool/candidateAdminPool/factPool; owner {label,
 * value}; publisher {containerId,imageId,publicationRoot}; preparer {containerId,
 * imageId}; and the existing signed initial-trust input shape. The observer's
 * candidate pool is separate from the publisher's reserved connection. All
 * stores are isolated/empty as checked below. Caller owns and closes the pools.
 * Every borrowed pool needs connectionTimeoutMillis in 1..5000 and query_timeout
 * in 1..10000; query failure is retained, never retried to obtain a pass.
 *
 * The preparer remains a /bin/sleep infinity namespace from the verified Fact
 * image. consumerLifecycle defaults to 'process' for existing callers: their
 * running sleep consumer retains its namespace and the driver owns exec PIDs.
 * With 'container', supply a CREATED consumer using the same image's normal
 * binary ENTRYPOINT and empty CMD. This driver starts/restarts that exact ID;
 * publisher continuity, signed authority and all business oracles are unchanged.
 * Both modes enforce UID/GID65532, immutable environment/mounts, read-only root,
 * dropped caps and finite limits. No normal-container check execs a replacement
 * server. After exit, only native metadata and the live publisher are inspected.
 *
 * Sequence: start publisher -> create observer -> prepare() -> caller creates
 * NEW consumer with returned exact file bind -> consume(containerId) -> restart()
 * -> invalidate() -> close(). Container stages return native lifecycle readback
 * {containerId,startedAt,hostPid,address,status,exitCode} for installer cleanup;
 * these observations are not startup authority. Caller closes publisher/pools and tears down
 * its exact containers/volume. No live container is mounted, no DSN is copied,
 * no ready callback grants authority. PREPARED reports actual completed prepare
 * and publication. There is no CLI that silently omits borrowed pools/topology.
 */
export async function createFactSecretConsumerJourney(input, options) {
  const operations = options.operations;
  if (operations) {
    assertFactSecretOperationsOwner(operations);
    assert.equal(typeof options.releaseOperationsGate, 'function');
  }
  const { controlAdminPool: admin, candidateAdminPool: candidate, factPool: facts } = options;
  const publisher = Object.freeze({ ...options.publisher });
  const preparer = Object.freeze({ ...options.preparer });
  const owner = Object.freeze({ ...options.owner });
  const consumerLifecycle = options.consumerLifecycle ?? 'process';
  const containerLifecycle = consumerLifecycle === 'container';
  const failures = failureOwner();
  const processes = new Set();
  const negativeRoot = `/tmp/fact-secret-negative-${randomUUID()}`;
  let state = 'INITIAL',
    busy = false,
    closed = false,
    closing,
    activeStage,
    blocker,
    pending;
  let expected, baseline, configurationBytes, recipientBytes, retained, originalInode;
  let publisherStart, preparerStart, publicationSource, publicationVolumeSource;
  let runtimeEnvironment,
    consumer,
    running,
    negativeCreated = false;

  async function inspect(id, imageId, kind, startedAt, requiredState = 'running') {
    assert.match(id, /^[0-9a-f]{64}$/u);
    assert.match(imageId, /^sha256:[0-9a-f]{64}$/u);
    const [value] = await nativeJson(['inspect', id]);
    assert.equal(value.Id, id);
    assert.equal(value.Image, imageId);
    assert.equal(value.Config.Labels?.[owner.label], owner.value);
    if (requiredState === 'running-or-exited')
      assert.ok(['running', 'exited'].includes(value.State.Status));
    else assert.equal(value.State.Status, requiredState);
    assert.equal(value.State.Running, value.State.Status === 'running');
    assert.equal(value.State.Paused, false);
    assert.equal(value.State.Restarting, false);
    assert.equal(value.State.Dead, false);
    assert.equal(value.State.OOMKilled, false);
    if (startedAt) assert.equal(value.State.StartedAt, startedAt);
    assert.equal(value.Config.User, '65532:65532');
    assert.equal(value.HostConfig.ReadonlyRootfs, true);
    assert.equal(value.HostConfig.Privileged, false);
    assert.deepEqual(value.HostConfig.CapDrop, ['ALL']);
    assert.ok(!value.HostConfig.CapAdd?.length);
    assert.ok(value.HostConfig.SecurityOpt?.some((v) => /^no-new-privileges(?::true)?$/u.test(v)));
    assert.ok(value.HostConfig.Memory > 0 && value.HostConfig.Memory <= 256 * 1024 ** 2);
    assert.equal(value.HostConfig.MemorySwap, value.HostConfig.Memory);
    assert.ok(value.HostConfig.NanoCpus > 0 && value.HostConfig.NanoCpus <= 1000000000);
    assert.ok(value.HostConfig.PidsLimit > 0 && value.HostConfig.PidsLimit <= 256);
    assert.equal(value.HostConfig.RestartPolicy.Name, 'no');
    assert.equal(value.HostConfig.PidMode, '');
    assert.ok(value.Mounts.every((m) => !m.Source?.endsWith('docker.sock')));
    if (kind === 'publisher') assert.equal(value.Config.Image, nodeImage);
    else {
      if (kind === 'consumer' && containerLifecycle) {
        assert.deepEqual(value.Config.Entrypoint, [binary]);
        assert.deepEqual(value.Config.Cmd ?? [], []);
        assert.equal(value.Path, binary);
        assert.deepEqual(value.Args, []);
      } else {
        assert.deepEqual(value.Config.Entrypoint, ['/bin/sleep']);
        assert.deepEqual(value.Config.Cmd, ['infinity']);
      }
      const env = environment(value);
      assert.equal(env.get('OPENPC_LOCAL_RUNTIME'), '1');
      assert.equal(env.get('OPENPC_FACT_BRIDGE_CONFIGURATION_FILE'), configurationPath);
      assert.equal(env.get('OPENPC_LOCAL_RUNTIME_FACT_SECRET_RECIPIENT_CONFIG'), recipientPath);
      assert.equal(env.get('OPENPC_FACT_LISTEN'), '0.0.0.0:8081');
      assert.equal(env.get('OPENPC_FACT_DATABASE_HOST'), 'fact-pg');
      assert.equal(env.get('OPENPC_FACT_DATABASE_PORT'), '5432');
      assert.equal(env.get('OPENPC_FACT_DATABASE_NAME'), 'openpc_facts');
      assert.equal(env.get('OPENPC_FACT_DATABASE_USER'), 'openpc_fact_runtime');
      for (const name of env.keys())
        if (name.startsWith('OPENPC_FACT_')) assert.ok(runtimeNames.includes(name));
      for (const name of runtimeNames) {
        assert.ok(env.get(name));
        if (runtimeEnvironment) assert.equal(env.get(name), runtimeEnvironment.get(name));
      }
    }
    return value;
  }
  const publisherCurrent = () =>
    inspect(publisher.containerId, publisher.imageId, 'publisher', publisherStart);
  const preparationCurrent = () =>
    inspect(preparer.containerId, preparer.imageId, 'preparer', preparerStart);
  const sessions = async () => {
    const observer = blocker ?? candidate;
    await observer.query('select pg_stat_clear_snapshot()');
    return observer.query(
      `select a.pid,a.query,a.wait_event_type,exists(
        select 1 from pg_locks l where l.pid=a.pid and l.locktype='relation'
        and l.database=a.datid and l.relation='candidate.fact_bridge_admission_v1'::regclass
        and l.mode='AccessShareLock' and not l.granted
      ) blocked_on_candidate from pg_stat_activity a
      where a.datname='openpc_candidate_index' and a.usename=$1`,
      [role],
    );
  };
  const login = async () =>
    (
      await (blocker ?? candidate).query('select rolcanlogin from pg_roles where rolname=$1', [
        role,
      ])
    ).rows[0]?.rolcanlogin;
  async function noBusinessEffects() {
    const connection = await facts.connect();
    try {
      await connection.query('begin read only');
      await connection.query(
        "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
        [baseline.installed.participantId, baseline.installed.privacyDomainId],
      );
      const counts = await connection.query(
        `select
        (select count(*)::int from facts.canonical_fact where participant_id=$1 and privacy_domain_id=$2) facts,
        (select count(*)::int from facts.outbox where participant_id=$1 and privacy_domain_id=$2) effects`,
        [baseline.installed.participantId, baseline.installed.privacyDomainId],
      );
      assert.deepEqual(counts.rows, [{ facts: 0, effects: 0 }]);
    } finally {
      try {
        await connection.query('rollback');
      } finally {
        connection.release();
      }
    }
  }
  async function installedRow() {
    const result = await admin.query(
      'select payload,cose,state from control.installed_secret_recipient where participant_id=$1 and privacy_domain_id=$2 and binding_digest=$3',
      [
        baseline.installed.participantId,
        baseline.installed.privacyDomainId,
        baseline.installed.signedBindingDigest,
      ],
    );
    assert.equal(result.rowCount, 1);
    return result.rows[0];
  }
  async function freshAuthority(minimumMs) {
    const row = await installedRow();
    assert.deepEqual(row, retained);
    const profile = verifyInstalledSecretRecipient(
      baseline.installed,
      row.payload,
      row.cose,
      Date.now(),
    );
    assert.equal(profile.validUntilMs, input.validUntilMs);
    assert.ok(profile.validUntilMs - Date.now() >= minimumMs, 'Insufficient remaining authority');
  }
  async function unpublished() {
    await publisherCurrent();
    assert.equal(await publicationState(publisher.containerId, publisher.publicationRoot), null);
    assert.equal(await login(), false);
    assert.equal((await sessions()).rowCount, 0);
    await noBusinessEffects();
  }
  async function publication(erased = false) {
    await publisherCurrent();
    const value = await publicationState(publisher.containerId, publisher.publicationRoot);
    assert.ok(value);
    assert.equal(value.uid, '65532');
    assert.equal(value.gid, '65532');
    assert.equal(value.links, '1');
    assert.equal(value.mode, erased ? '0' : '400');
    assert.equal(value.size, String(erased ? 0 : expected.length));
    if (originalInode) assert.ok(sameInode(value, originalInode));
    if (!erased) {
      const bytes = await containerFile(
        publisher.containerId,
        join(publisher.publicationRoot, 'candidate-url'),
        4096,
      );
      try {
        assert.deepEqual(bytes, expected);
      } finally {
        bytes.fill(0);
      }
    }
    return value;
  }
  async function immutableInputs(id) {
    for (const [path, original] of [
      [configurationPath, configurationBytes],
      [recipientPath, recipientBytes],
    ]) {
      const bytes = await containerFile(id, path, 131072);
      try {
        assert.deepEqual(bytes, original);
      } finally {
        bytes.fill(0);
      }
    }
    const certificate = await containerFile(
      id,
      baseline.configuration.client_chain_der_files[0],
      65536,
    );
    try {
      assert.deepEqual(
        certificate,
        new X509Certificate(Buffer.from(input.tls.certificate, 'base64')).raw,
      );
    } finally {
      certificate.fill(0);
    }
  }
  function retainedBind(current) {
    assertFactSecretPublishedBind(current, publicationSource, publicationVolumeSource);
  }
  async function mounted(erased = false) {
    const current = containerLifecycle
      ? await consumerCurrent()
      : await inspect(consumer.id, preparer.imageId, 'consumer', consumer.startedAt);
    retainedBind(current);
    const value = await statFile(consumer.id, mountPath);
    assert.deepEqual(value, await publication(erased));
    assert.ok(sameInode(value, originalInode));
    const realpath = await docker(
      execArgs(consumer.id, '/usr/bin/readlink', '-f', '--', mountPath),
    );
    try {
      assert.equal(realpath.toString().trim(), mountPath);
    } finally {
      realpath.fill(0);
    }
    const fsType = await docker(
      execArgs(consumer.id, '/usr/bin/stat', '-f', '--format=%t', '--', mountPath),
    );
    try {
      assert.equal(fsType.toString().trim(), '1021994');
    } finally {
      fsType.fill(0);
    }
    const bytes = await containerFile(consumer.id, '/proc/self/mountinfo', 131072);
    try {
      const mounts = bytes
        .toString()
        .split('\n')
        .map((line) => line.split(' '));
      assert.ok(
        mounts.some(
          (fields) =>
            decodeMount(fields[4] ?? '') === mountPath && fields[5]?.split(',').includes('ro'),
        ),
      );
    } finally {
      bytes.fill(0);
    }
    if (!erased) {
      const content = await containerFile(consumer.id, mountPath, 4096);
      try {
        assert.deepEqual(content, expected);
      } finally {
        content.fill(0);
      }
    }
    await immutableInputs(consumer.id);
  }

  function containerConfiguration(value) {
    // Docker updates, replacement binds and command changes must not be hidden
    // by a legitimate new StartedAt. Addresses/processes are checked separately.
    return factSecretContainerConfiguration(value);
  }
  async function consumerCurrent(requiredState = 'running', allowNewStart = false) {
    assert.ok(containerLifecycle && consumer);
    const value = await inspect(
      consumer.id,
      preparer.imageId,
      'consumer',
      allowNewStart ? undefined : consumer.startedAt,
      requiredState,
    );
    assert.deepEqual(containerConfiguration(value), consumer.configuration);
    retainedBind(value);
    await publisherCurrent();
    return value;
  }
  function lifecycleReadback(value) {
    return Object.freeze({
      containerId: value.Id,
      startedAt: value.State.StartedAt,
      hostPid: value.State.Pid,
      address: consumer.address ?? null,
      status: value.State.Status,
      exitCode: value.State.ExitCode,
    });
  }
  function refreshConsumer(value) {
    assert.ok(
      Number.isFinite(Date.parse(value.State.StartedAt)) && Date.parse(value.State.StartedAt) > 0,
    );
    consumer.startedAt = value.State.StartedAt;
    consumer.started = true;
    if (value.State.Running) {
      assert.equal(Object.keys(value.NetworkSettings.Networks).length, 1);
      const address = value.NetworkSettings.Networks[consumer.network]?.IPAddress;
      assert.equal(isIP(address), 4);
      consumer.address = address;
      consumer.base = `http://${address}:8081`;
      assert.ok(value.State.Pid > 0);
    } else assert.equal(value.State.Pid, 0);
  }
  async function containerProcessIdentity() {
    const current = await consumerCurrent();
    const executable = await docker(execArgs(consumer.id, '/usr/bin/readlink', '/proc/1/exe'));
    const bytes = await containerFile(consumer.id, '/proc/1/stat', 4096);
    try {
      assert.equal(executable.toString().trim(), binary);
      const text = bytes.toString();
      assert.ok(text.startsWith('1 ('));
      const fields = text
        .slice(text.lastIndexOf(') ') + 2)
        .trim()
        .split(' ');
      assert.match(fields[19], /^[1-9][0-9]*$/u);
      assert.notEqual(fields[0], 'Z');
      return { hostPid: current.State.Pid, start: fields[19], startedAt: current.State.StartedAt };
    } finally {
      executable.fill(0);
      bytes.fill(0);
    }
  }
  async function packagedHealth() {
    await consumerCurrent();
    const result = await docker(execArgs(consumer.id, binary, 'healthcheck'));
    try {
      assert.equal(result.length, 0);
    } finally {
      result.fill(0);
    }
    assert.equal(await ready(), true);
  }
  async function awaitContainerReady() {
    let phase = 'native-readiness';
    try {
      await wait(async () => {
        await consumerCurrent(); // An actual early exit fails, rather than timing out as not-ready.
        return ready();
      });
      emit('OBSERVED', 'native-http-readiness');
      phase = 'native-packaged-health';
      await packagedHealth();
      phase = 'native-mounted-publication';
      await mounted();
      phase = 'native-process-identity';
      const identity = await containerProcessIdentity();
      emit('OBSERVED', 'native-health-mount-process-verified');
      return identity;
    } catch (error) {
      throw failures.capture(error, phase);
    }
  }
  async function startContainer() {
    await freshAuthority(15000);
    await consumerCurrent('created');
    await publication();
    const previous = consumer.startedAt;
    const result = await docker(['start', consumer.id]);
    result.fill(0);
    emit('OBSERVED', 'native-container-started-awaiting-immutable-readback');
    const current = await consumerCurrent('running', true);
    assert.notEqual(current.State.StartedAt, previous);
    refreshConsumer(current);
    emit('OBSERVED', 'native-container-immutable-readback-verified');
    if (operations) {
      await operations.installStarted(current, input);
      // This callback only releases the private publication barrier AFTER the
      // actual owned association has committed; it never reports readiness.
      await options.releaseOperationsGate();
    }
    consumer.process = await awaitContainerReady();
  }
  async function restartContainer() {
    await freshAuthority(15000);
    await mounted();
    await packagedHealth();
    const previous = await containerProcessIdentity();
    const result = await docker(['restart', '--time', '5', consumer.id]);
    result.fill(0);
    const current = await consumerCurrent('running', true);
    assert.notEqual(current.State.StartedAt, previous.startedAt);
    refreshConsumer(current);
    consumer.process = await awaitContainerReady();
    assert.notDeepEqual(consumer.process, previous);
    assert.notEqual(consumer.process.start, previous.start);
    // Docker may need its bounded kill fallback; this is container restart,
    // not evidence of graceful signal handling in the packaged service.
    emit('OBSERVED', 'native-container-restarted-no-graceful-shutdown-claim');
  }
  async function containerExited(expectedCode, noReadiness = false) {
    let current;
    await wait(async () => {
      current = await consumerCurrent('running-or-exited');
      if (noReadiness) {
        if (current.State.Running) refreshConsumer(current);
        assert.equal(await ready(), false);
        assert.equal(await login(), false);
        assert.equal((await sessions()).rowCount, 0);
        await publication(true);
      }
      return current.State.Status === 'exited';
    });
    assert.equal(current.State.Pid, 0);
    assert.equal(current.State.ExitCode, expectedCode);
    assert.ok(
      Number.isFinite(Date.parse(current.State.FinishedAt)) &&
        Date.parse(current.State.FinishedAt) > 0,
    );
    return current;
  }
  async function containerFailure(classification) {
    await consumerCurrent('exited');
    // Docker's log copier can finish after process exit. Poll only this bounded
    // readback; never repeat the failed startup to obtain a diagnostic record.
    await wait(() => readFactSecretRuntimeFailure(consumer.id, consumer.startedAt, classification));
  }
  async function stoppedMount() {
    // The consumer namespace has gone. Do not exec/stat inside it or invent a
    // replacement observer namespace. Retained bind metadata is immutable, and
    // the still-live publisher proves erasure of the original observed inode.
    await consumerCurrent('exited');
    const erased = await publication(true);
    assert.ok(sameInode(erased, originalInode));
    await immutableInputs(preparer.containerId);
    await immutableInputs(publisher.containerId);
  }
  async function deniedContainerStart() {
    await stoppedMount();
    assert.equal(await ready(), false);
    assert.equal(await login(), false);
    assert.equal((await sessions()).rowCount, 0);
    const previous = consumer.startedAt;
    const result = await docker(['start', consumer.id]);
    result.fill(0); // Docker start success is not service readiness.
    const current = await consumerCurrent('running-or-exited', true);
    assert.notEqual(current.State.StartedAt, previous);
    refreshConsumer(current);
    await containerExited(1, true);
    await containerFailure('fact installed secret recipient unavailable');
    await stoppedMount();
  }
  async function stopConsumerContainer() {
    if (!containerLifecycle || !consumer) return;
    const current = await consumerCurrent(consumer.started ? 'running-or-exited' : 'created');
    if (!current.State.Running) return;
    const result = await docker(['stop', '--time', '5', consumer.id]);
    result.fill(0);
    const stopped = await consumerCurrent('exited');
    assert.equal(stopped.State.Pid, 0);
    emit('OBSERVED', `owned-container-stopped-exit-${stopped.State.ExitCode}`);
  }

  // Retain the actual exec PID/starttime before exec replaces the shell. These
  // are kernel observations, not readiness or authorization supplied by a caller.
  function launch(id, args = [], config = configurationPath) {
    const record = dockerProcess([
      'exec',
      '-i',
      '--user',
      '65532:65532',
      '-e',
      `OPENPC_FACT_BRIDGE_CONFIGURATION_FILE=${config}`,
      id,
      '/bin/sh',
      '-c',
      'printf "FACT_EXEC|%s|%s\\n" "$$" "$(awk \'{print $22}\' /proc/$$/stat)"; exec "$@"',
      'fact-exec',
      binary,
      ...args,
    ]);
    record.containerId = id;
    processes.add(record);
    return record;
  }
  function processIdentity(record) {
    const bytes = Buffer.concat(record.chunks);
    try {
      const match = /^FACT_EXEC\|([1-9][0-9]*)\|([1-9][0-9]*)\n/u.exec(bytes.toString());
      if (match) assert.ok(Number(match[1]) > 1);
      return match ? { pid: match[1], start: match[2] } : undefined;
    } finally {
      bytes.fill(0);
    }
  }
  async function exited(record) {
    await wait(() => record.result !== undefined);
    assert.equal(record.failed, false);
    assert.ok(processIdentity(record));
    return record.result;
  }
  async function stop(record) {
    if (!record) return;
    await wait(() => record.result !== undefined || processIdentity(record) !== undefined);
    const identity = processIdentity(record);
    // A lost Docker connection without a PID is an unresolved owned execution,
    // even if the local client exited. Retain the container for its installer.
    assert.ok(identity);
    await docker(
      execArgs(
        record.containerId,
        '/bin/sh',
        '-c',
        stopFactProcess,
        'fact-stop',
        identity.pid,
        identity.start,
        binary,
      ),
    );
    if (!record.result) await exited(record);
  }
  async function releaseRead() {
    if (blocker) {
      const held = blocker;
      blocker = undefined;
      try {
        await held.query('rollback');
      } finally {
        held.release(true);
      }
    }
  }
  const ready = async () =>
    fetch(`${consumer.base}/readyz`, { signal: AbortSignal.timeout(500) }).then(
      (response) => response.status === 200,
      () => false,
    );
  async function start() {
    await freshAuthority(5000);
    await mounted();
    assert.equal(
      await fetch(`${consumer.base}/healthz`, { signal: AbortSignal.timeout(500) }).then(
        () => true,
        () => false,
      ),
      false,
    );
    running = launch(consumer.id);
    await wait(async () => {
      if (running.result) throw new Error('Fact stopped before readiness');
      return ready();
    });
    assert.ok(processIdentity(running));
  }
  async function beginRead() {
    await freshAuthority(input.mode === 'consumer-revocation' ? 12000 : 2000);
    blocker = await candidate.connect();
    await blocker.query('begin');
    await blocker.query("set local lock_timeout='2s'");
    await blocker.query('lock table candidate.fact_bridge_admission_v1 in access exclusive mode');
    const token = await containerFile(
      consumer.id,
      runtimeEnvironment.get('OPENPC_FACT_INTERNAL_TOKEN_FILE'),
      4096,
    );
    let completed;
    try {
      pending = fetch(
        `${consumer.base}/internal/v1/fact-source-projection-bridge?partitionId=${localOperationId()}&candidateSequence=1`,
        {
          headers: {
            'authorization': `Bearer ${token.toString().trim()}`,
            'openpc-api-version': '1',
            'openpc-participant-id': `urn:openpc:participant:${baseline.installed.participantId}`,
            'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${baseline.installed.privacyDomainId}`,
            'x-request-id': localOperationId(),
            'x-correlation-id': localOperationId(),
            'x-openpc-action-intent': 'ACT-FACT_ARTIFACTS_READ_COLLECTION-V1',
            'openpc-action-intent-digest':
              'sha256:a671fa20f95424230312b71c2c6e9198f9add32f0c7f874d216f2ad1b7c7c452',
          },
          signal: AbortSignal.timeout(125000),
        },
      )
        .then(async (response) => ({ status: response.status, code: (await response.json()).code }))
        .catch(() => ({ status: 0 }))
        .then((result) => {
          completed = result;
          return result;
        });
    } finally {
      token.fill(0);
    }
    await wait(async () => {
      if (completed) {
        // Status alone is safe; response text, credential-bearing assertions
        // and raw errors remain private. An early denial cannot prove a read
        // held at the intended database boundary.
        emit('OBSERVED', `candidate-read-returned-${completed.status}`);
        throw failures.capture(
          new Error('Read ended before database barrier'),
          'candidate-read-barrier',
        );
      }
      return (await sessions()).rows.some(
        (row) => row.wait_event_type === 'Lock' && row.blocked_on_candidate === true,
      );
    });
    // Expired authority cannot substitute for observing the intended invalidation.
    await freshAuthority(input.mode === 'consumer-revocation' ? 12000 : 1000);
  }
  async function positiveRead() {
    await beginRead();
    await releaseRead();
    assert.deepEqual(await pending, { status: 404, code: 'PC-AUTH-0005' });
    pending = undefined;
    await wait(async () => (await sessions()).rowCount === 0);
    await noBusinessEffects();
  }
  function stage(required, next, run) {
    failures.assertHealthy();
    if (closed || busy || state !== required)
      throw failures.capture(new Error('Invalid Fact journey stage'), 'stage-order');
    busy = true;
    activeStage = (async () => {
      try {
        const result = await run();
        state = next;
        return result;
      } catch (error) {
        throw failures.capture(error, next.toLowerCase());
      } finally {
        busy = false;
      }
    })();
    return activeStage;
  }
  const close = () => {
    closing ??= (async () => {
      closed = true;
      await activeStage?.catch(() => undefined);
      const results = await Promise.allSettled([
        ...[...processes].map(stop),
        stopConsumerContainer(),
      ]);
      results.push(...(await Promise.allSettled([releaseRead()])));
      if (pending) results.push(...(await Promise.allSettled([pending])));
      if (negativeCreated)
        results.push(
          ...(await Promise.allSettled([
            docker(execArgs(preparer.containerId, '/bin/rm', '-r', '--', negativeRoot)),
          ])),
        );
      for (const record of processes) eraseOutput(record);
      expected?.fill(0);
      configurationBytes?.fill(0);
      recipientBytes?.fill(0);
      if (results.some((result) => result.status === 'rejected')) {
        emit('UNKNOWN', 'observer-cleanup-installer-retains-containers');
        failures.capture(new Error('Owned exec or read cleanup unresolved'), 'observer-cleanup');
      }
      failures.assertHealthy();
      if (state !== 'VERIFIED')
        throw failures.capture(new Error('Incomplete required stages'), 'incomplete');
      emit(
        'PASS',
        operations
          ? 'operations-source-invalidation-installer-cleanup-pending'
          : `${input.mode}-${consumerLifecycle}-restart-installer-cleanup-pending`,
      );
    })();
    return closing;
  };

  try {
    input = structuredClone(input);
    assert.ok(['process', 'container'].includes(consumerLifecycle));
    for (const pool of [admin, candidate, facts]) borrowedPool(pool);
    assert.match(owner.label, /^[a-zA-Z0-9_.-]+$/u);
    assert.ok(typeof owner.value === 'string' && owner.value.length > 0);
    assert.ok(isAbsolute(publisher.publicationRoot) && !publisher.publicationRoot.includes('\0'));
    assert.notEqual(publisher.containerId, preparer.containerId);
    const pub = await publisherCurrent(),
      prep = await preparationCurrent();
    if (containerLifecycle) {
      const [image] = await nativeJson(['image', 'inspect', preparer.imageId]);
      assert.equal(image.Id, preparer.imageId);
      assert.deepEqual(image.Config.Entrypoint, [binary]);
      assert.deepEqual(image.Config.Cmd ?? [], []);
    }
    publisherStart = pub.State.StartedAt;
    preparerStart = prep.State.StartedAt;
    runtimeEnvironment = environment(prep);
    const volumes = pub.Mounts.filter((mount) => mount.Destination === publisher.publicationRoot);
    assert.equal(volumes.length, 1);
    const volume = volumes[0];
    assert.equal(volume.Type, 'volume');
    assert.equal(volume.RW, true);
    const [description] = await nativeJson(['volume', 'inspect', volume.Name]);
    assert.equal(description.Labels?.[owner.label], owner.value);
    assert.equal(description.Driver, 'local');
    assert.equal(description.Mountpoint, volume.Source);
    assert.deepEqual(description.Options, {
      type: 'tmpfs',
      device: 'tmpfs',
      o: 'size=64m,nosuid,nodev,noexec,uid=65532,gid=65532,mode=0700',
    });
    publicationVolumeSource = volume.Source;
    publicationSource = join(volume.Source, 'candidate-url');
    configurationBytes = await containerFile(preparer.containerId, configurationPath, 131072);
    recipientBytes = await containerFile(preparer.containerId, recipientPath, 16384);
    baseline = installation(input, configurationBytes, recipientBytes);
    const pubAddresses = Object.values(pub.NetworkSettings.Networks).map(
      (network) => network.IPAddress,
    );
    assert.ok(pubAddresses.includes(baseline.recipient.addresses[0]));
    await immutableInputs(preparer.containerId);
    await immutableInputs(publisher.containerId);
    expected = Buffer.from(input.material, 'base64');
    assert.ok(expected.length > 0 && expected.length <= 4096);
    const material = new URL(expected.toString()),
      candidateUrl = new URL(input.candidateUrl);
    assert.equal(material.hostname, 'candidate-index-pg');
    assert.equal(material.port, '5432');
    assert.equal(material.username, role);
    assert.equal(material.pathname, '/openpc_candidate_index');
    assert.equal(candidateUrl.username, material.username);
    assert.equal(candidateUrl.password, material.password);
    assert.equal(candidateUrl.pathname, material.pathname);
    await assertEmptyFactCandidateSlice(candidate, baseline.installed);
    assert.deepEqual((await facts.query('select current_database() name,current_user role')).rows, [
      { name: 'openpc_facts', role: 'openpc_fact_runtime' },
    ]);
    retained = await installedRow();
    assert.equal(retained.state, 'ACTIVE');
    await freshAuthority(15000);
    await unpublished();
    state = 'RESERVED';
  } catch (error) {
    const primary = failures.capture(error, 'observer-preflight');
    await close().catch(() => undefined);
    throw primary;
  }

  return Object.freeze({
    prepare: () =>
      stage('RESERVED', 'PREPARED', async () => {
        await preparationCurrent();
        // Retain cleanup ownership even if the Docker reply is lost after mkdir.
        negativeCreated = true;
        await docker(execArgs(preparer.containerId, '/bin/mkdir', '-m', '700', '--', negativeRoot));
        const { configuration, recipient } = baseline;
        const negatives = [
          ...[
            { reference: `${input.reference.slice(0, -2)}v2`, version: 'v2' },
            { version: 'v2' },
            { signed_binding_digest: `sha256:${'ef'.repeat(32)}` },
            { installation_digest: `sha256:${'ed'.repeat(32)}` },
            { generation: String(BigInt(recipient.generation) + 1n) },
            { workload_credential_id: localOperationId() },
            { workload_credential_epoch: String(BigInt(recipient.workload_credential_epoch) + 1n) },
          ].map((changed) => ({
            ...configuration,
            candidate_secret_recipient: { ...recipient, ...changed },
          })),
          { ...configuration, participant_id: localOperationId() },
          { ...configuration, privacy_domain_id: localOperationId() },
        ];
        for (const [index, changed] of negatives.entries()) {
          await freshAuthority(15000);
          const path = `${negativeRoot}/${index}.json`;
          const bytes = Buffer.from(JSON.stringify(changed));
          try {
            await docker(
              [
                'exec',
                '-i',
                '--user',
                '65532:65532',
                preparer.containerId,
                '/bin/sh',
                '-c',
                'umask 077; set -C; cat > "$1"; chmod 400 "$1"',
                'fact-input',
                path,
              ],
              bytes,
            );
          } finally {
            bytes.fill(0);
          }
          assert.equal(
            (await exited(launch(preparer.containerId, ['prepare-secret'], path))).code,
            1,
          );
          await unpublished();
        }
        await freshAuthority(15000);
        await immutableInputs(preparer.containerId);
        assert.equal((await exited(launch(preparer.containerId, ['prepare-secret']))).code, 0);
        assert.equal(await login(), true);
        assert.equal((await sessions()).rowCount, 0);
        originalInode = await publication();
        await noBusinessEffects();
        emit('PREPARED', 'installer-create-consumer-with-original-inode');
        return Object.freeze({
          type: 'bind',
          source: publicationSource,
          target: mountPath,
          readOnly: true,
        });
      }),
    consume: (containerId) =>
      stage('PREPARED', 'CONSUMED', async () => {
        assert.notEqual(containerId, publisher.containerId);
        assert.notEqual(containerId, preparer.containerId);
        const value = await inspect(
          containerId,
          preparer.imageId,
          'consumer',
          undefined,
          containerLifecycle ? 'created' : 'running',
        );
        const pub = await publisherCurrent();
        const sharedNetworks = (
          containerLifecycle
            ? [value.HostConfig.NetworkMode]
            : Object.keys(value.NetworkSettings.Networks)
        ).filter((name) => pub.NetworkSettings.Networks[name]);
        assert.equal(sharedNetworks.length, 1);
        consumer = {
          id: containerId,
          startedAt: value.State.StartedAt,
          network: sharedNetworks[0],
          configuration: structuredClone(containerConfiguration(value)),
          started: false,
        };
        if (containerLifecycle) await startContainer();
        else {
          const address = value.NetworkSettings.Networks[sharedNetworks[0]].IPAddress;
          assert.equal(isIP(address), 4);
          consumer.base = `http://${address}:8081`;
          await start();
        }
        if (operations) {
          await operations.positive();
          await noBusinessEffects();
        } else await positiveRead();
        emit(
          'OBSERVED',
          containerLifecycle ? 'packaged-container-consumption' : 'packaged-consumption',
        );
        if (containerLifecycle) return lifecycleReadback(await consumerCurrent());
      }),
    restart: () =>
      stage('CONSUMED', 'RESTARTED', async () => {
        if (containerLifecycle) await restartContainer();
        else {
          const previous = processIdentity(running);
          await stop(running);
          await start();
          assert.notDeepEqual(processIdentity(running), previous);
        }
        await mounted();
        await positiveRead();
        emit('OBSERVED', `same-pins-${consumerLifecycle}-restart`);
        if (containerLifecycle) return lifecycleReadback(await consumerCurrent());
      }),
    observeOperationsInvalidation: (cause) =>
      stage('CONSUMED', 'VERIFIED', async () => {
        assert.ok(operations && containerLifecycle);
        assert.ok(
          ['revocation', 'exit', 'backend-close', 'expiry', 'stale-restart'].includes(cause),
        );
        await operations.positive();
        await freshAuthority(cause === 'revocation' ? 12000 : 1000);
        if (cause === 'revocation') {
          const connection = await admin.connect();
          try {
            await connection.query('begin');
            await connection.query(
              "select pg_advisory_xact_lock(hashtextextended('secret-recipient:'||$1::text||':'||$2::text,0))",
              [baseline.installed.participantId, baseline.installed.privacyDomainId],
            );
            assert.equal(
              (
                await connection.query(
                  "update control.installed_secret_recipient set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and binding_digest=$3 and state='ACTIVE'",
                  [
                    baseline.installed.participantId,
                    baseline.installed.privacyDomainId,
                    baseline.installed.signedBindingDigest,
                  ],
                )
              ).rowCount,
              1,
            );
            await connection.query('commit');
          } catch (error) {
            const primary = failures.capture(error, 'operations-recipient-revocation');
            await connection.query('rollback').catch(() => {
              emit('UNKNOWN', 'operations-recipient-rollback');
            });
            throw primary;
          } finally {
            connection.release();
          }
          assert.ok(Date.now() < input.validUntilMs);
        } else if (cause === 'backend-close') await operations.terminateProof();
        else if (cause === 'expiry') {
          // Pause the original native process to prevent automatic renewal;
          // this is the real process, never a stopped/replaced source fixture.
          await docker(['kill', '--signal', 'STOP', consumer.id]);
          try {
            await operations.waitForExpiry();
            await operations.unavailable();
          } catch (error) {
            throw failures.capture(error, 'operations-expiry');
          } finally {
            await docker(['kill', '--signal', 'CONT', consumer.id]).catch((error) => {
              emit('UNKNOWN', 'operations-resume-original-process');
              throw failures.capture(error, 'operations-resume-original-process');
            });
          }
        } else await stopConsumerContainer();
        if (cause !== 'expiry') await operations.unavailable({ beforeExpiry: true });
        if (cause === 'stale-restart') {
          const previous = consumer.startedAt;
          const result = await docker(['start', consumer.id]);
          result.fill(0);
          const current = await consumerCurrent('running-or-exited', true);
          assert.notEqual(current.State.StartedAt, previous);
          refreshConsumer(current);
          await containerExited(1);
          await operations.unavailable();
        }
        await noBusinessEffects();
        return lifecycleReadback(await consumerCurrent('running-or-exited'));
      }),
    invalidate: () =>
      stage('RESTARTED', 'VERIFIED', async () => {
        await beginRead();
        if (input.mode === 'consumer-revocation') {
          const connection = await admin.connect();
          try {
            await connection.query('begin');
            await connection.query(
              "select pg_advisory_xact_lock(hashtextextended('secret-recipient:'||$1::text||':'||$2::text,0))",
              [baseline.installed.participantId, baseline.installed.privacyDomainId],
            );
            const changed = await connection.query(
              "update control.installed_secret_recipient set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and binding_digest=$3 and state='ACTIVE'",
              [
                baseline.installed.participantId,
                baseline.installed.privacyDomainId,
                baseline.installed.signedBindingDigest,
              ],
            );
            assert.equal(changed.rowCount, 1);
            await connection.query('commit');
          } catch (error) {
            await connection.query('rollback');
            throw error;
          } finally {
            connection.release();
          }
        }
        await wait(
          async () => !(await login()) && (await sessions()).rowCount === 0,
          input.mode === 'consumer-expiry'
            ? Math.max(12000, input.validUntilMs - Date.now() + 5000)
            : 12000,
        );
        if (input.mode === 'consumer-revocation') assert.ok(Date.now() < input.validUntilMs);
        assert.notEqual((await pending).status, 200);
        pending = undefined;
        await releaseRead();
        if (containerLifecycle) {
          await containerExited(1);
          await containerFailure('fact secret recipient revoked');
        } else assert.equal((await exited(running)).code, 1);
        assert.equal(await ready(), false);
        const replacement = new Client({
          connectionString: input.candidateUrl,
          connectionTimeoutMillis: 2000,
        });
        replacement.on('error', () => {});
        try {
          await assert.rejects(replacement.connect());
        } finally {
          await replacement.end();
        }
        if (containerLifecycle) await stoppedMount();
        else await mounted(true);
        assert.equal((await exited(launch(preparer.containerId, ['prepare-secret']))).code, 1);
        if (containerLifecycle) await deniedContainerStart();
        else assert.equal((await exited(launch(consumer.id))).code, 1);
        assert.equal(await ready(), false);
        assert.equal(await login(), false);
        assert.equal((await sessions()).rowCount, 0);
        assert.deepEqual(await installedRow(), {
          ...retained,
          state: input.mode === 'consumer-revocation' ? 'REVOKED' : 'ACTIVE',
        });
        if (containerLifecycle) await stoppedMount();
        else await mounted(true);
        await noBusinessEffects();
        if (containerLifecycle) return lifecycleReadback(await consumerCurrent('exited'));
      }),
    close,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  emit('BLOCKED', 'installer-must-import-stages-with-owned-pools-and-containers');
  process.exitCode = 1;
}
