import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as retryDelay } from 'node:timers/promises';
import { Pool } from 'pg';
import { isRuntimeSourceProducerContention } from '../../../services/control-api/src/configuration/persistence/types.ts';
import { sourceScope } from './runtime-source-bootstrap.mjs';
import { runtimeArtifactDispositionSelection } from '../../../services/control-api/src/evidence/runtime-artifact-disposition-contract.ts';
import { runtimeArtifactRetirementSelection } from '../../../services/control-api/src/evidence/runtime-artifact-deletion-contracts.ts';

// Connected database regression after genuine import/archive/retention. No
// authority or business effect is seeded. Every injected fault is rolled back
// in the authenticated runtime connection before the original is rechecked.
const [root, policyUrn, sourceCase = 'original', stage = 'disposition'] = process.argv.slice(2);
assert.ok(['original', 'live-replay'].includes(sourceCase));
assert.ok(['disposition', 'retirement'].includes(stage));
const physical = stage === 'retirement';
const output = join(
  root,
  'evidence/runtime-bootstrap/runtime-source-disposition',
  sourceCase === 'original' ? '' : sourceCase,
);
const original = JSON.parse(await readFile(join(output, 'old-import.json'))).source;
const successor = JSON.parse(await readFile(join(output, 'successor-import.json'))).source;
const policy = policyUrn?.replace(/^urn:openpc:resource:/u, '');
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
for (const value of [
  original.id,
  successor.id,
  policy,
  sourceScope.participant,
  sourceScope.privacy,
])
  assert.match(value, uuid);
const pool = async (user, secret) =>
  new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user,
    password: (await readFile(join(root, 'secrets', secret), 'utf8')).trim(),
    max: 1,
    statement_timeout: 5000,
    query_timeout: 7000,
  });
const admin = await pool('openpc_control', 'control_pg_password.txt');
const runtime = await pool('openpc_configuration_runtime', 'control_api_runtime_db_password.txt');
const worker = await pool('openpc_local_control_worker', 'control_worker_runtime_db_password.txt');
const api = await runtime.connect();
const read = physical
  ? 'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1'
  : 'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1';
const dispose = physical
  ? 'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1'
  : 'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1';
const unknown = '018f0000-0000-7000-8000-000000009999';
const helper = (input = original.id) =>
  api.query('select openpc.runtime_artifact_archive_payloads_match($1) matches', [input]);
const selection = (input = original.id) =>
  physical
    ? api.query('select openpc.runtime_artifact_retirement_selection($1,$2) value', [
        policy,
        input === original.id ? null : input,
      ])
    : api.query('select openpc.runtime_artifact_disposition_selection($1,$2) value', [
        input,
        policy,
      ]);
const begin = async ({
  action = read,
  participant = sourceScope.participant,
  privacy = sourceScope.privacy,
  lock = true,
  isolation = 'read committed',
  role,
} = {}) => {
  assert.ok(['read committed', 'repeatable read', 'serializable'].includes(isolation));
  for (let attempt = 0; attempt < 3; attempt++) {
    await api.query(`begin isolation level ${isolation}`);
    if (role) {
      assert.equal(role, 'openpc_control_runtime');
      await api.query('set local role openpc_control_runtime');
    }
    await api.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
      participant,
      privacy,
      original.id,
      action,
    ]);
    if (!lock) return;
    try {
      await api.query('select openpc.lock_runtime_artifact_disposition()');
      return;
    } catch (error) {
      // No scenario, injected fault or authority consumption has begun. Match
      // the public owner's exact pre-gate classification and finite backoff.
      await api.query('rollback');
      if (attempt === 2 || !isRuntimeSourceProducerContention(error)) throw error;
      process.stdout.write(`OPENPC_SOURCE_SELECTION|RETRY|producer-gate|attempt=${attempt + 1}\n`);
      await retryDelay(25 * 2 ** attempt);
    }
  }
};
const scenario = async (name, options, check) => {
  try {
    await begin(options);
    await check();
  } finally {
    await api.query('rollback');
  }
  process.stdout.write(`OPENPC_SOURCE_SELECTION|PASS|${name}\n`);
};
const positive = async () => {
  assert.equal((await helper()).rows[0].matches, true);
  const raw = (await selection()).rows[0].value;
  const value = physical
    ? runtimeArtifactRetirementSelection.parse(raw)
    : runtimeArtifactDispositionSelection.parse(raw).observation;
  assert.equal(value.source.runtimeConfigurationInputId, original.id);
  assert.equal(value.source.configurationDigest, original.digest);
  assert.ok(value.archiveSegments.length > 0);
  if (physical) {
    assert.equal(value.priorCursor, null);
    assert.equal(value.nextInput.runtimeConfigurationInputId, successor.id);
  }
};
const schema = `openpc_archive_test_${randomBytes(8).toString('hex')}`;
let faultOwnerCreated = false;
try {
  const {
    rows: [roles],
  } = await api.query('select current_user current,session_user session');
  assert.deepEqual(roles, {
    current: 'openpc_configuration_runtime',
    session: 'openpc_configuration_runtime',
  });
  for (const action of [read, dispose]) {
    await scenario(`complete-${action}`, { action }, positive);
    await scenario(`set-role-${action}`, { action, role: 'openpc_control_runtime' }, positive);
  }
  await scenario('missing-input-and-archive', {}, async () => {
    for (const input of [null, unknown, successor.id])
      assert.equal((await helper(input)).rows[0].matches, false);
    await assert.rejects(
      selection(successor.id),
      physical ? { code: 'P0002' } : { message: 'RUNTIME-DISPOSITION-SELECTED_INPUT' },
    );
  });
  for (const [name, options] of [
    ['foreign-participant', { participant: unknown }],
    ['foreign-privacy', { privacy: unknown }],
  ])
    await scenario(name, options, async () =>
      assert.equal((await helper()).rows[0].matches, false),
    );
  await scenario('missing-fences', { lock: false }, () =>
    assert.rejects(helper(), { message: 'RUNTIME-ARTIFACT-OBSERVATION-FENCE' }),
  );
  await scenario('wrong-action', { action: 'ACT-EVIDENCE_EXPORT_RECORDS-V1', lock: false }, () =>
    assert.rejects(helper(), { message: 'PC-AUTH-0005' }),
  );
  for (const isolation of ['repeatable read', 'serializable'])
    await scenario(isolation, { isolation, lock: false }, () =>
      assert.rejects(helper(), { message: 'PC-AUTH-0005' }),
    );
  await scenario('raw-payload-remains-withheld', {}, () =>
    assert.rejects(
      api.query('select encrypted_segment from control.evidence_segment_payload limit 1'),
      { code: '42501' },
    ),
  );
  await assert.rejects(helper(), { code: 'P0001' });
  await assert.rejects(
    worker.query('select openpc.runtime_artifact_archive_payloads_match($1)', [original.id]),
    { code: '42501' },
  );
  // SET ROLE does not turn a privileged connection into an authenticated API
  // session. The definer must inspect session_user, not its own current_user.
  const administrator = await admin.connect();
  try {
    await administrator.query('begin');
    await administrator.query('set local role openpc_control_runtime');
    await administrator.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
      sourceScope.participant,
      sourceScope.privacy,
      original.id,
      read,
    ]);
    await assert.rejects(
      administrator.query('select openpc.runtime_artifact_archive_payloads_match($1)', [
        original.id,
      ]),
      { message: 'PC-AUTH-0005' },
    );
  } finally {
    await administrator.query('rollback');
    administrator.release();
  }
  process.stdout.write('OPENPC_SOURCE_SELECTION|PASS|unauthorized-direct-and-set-role\n');

  // Test-only, random schema and hard-bound source. This grants no arbitrary
  // SQL or committed effect: the runtime caller rolls every fault transaction
  // back, and the private fixture function is dropped in finally. Replication
  // mode is local to the fault function; the real selector runs with origin.
  await admin.query(`create schema ${schema}; revoke all on schema ${schema} from public`);
  faultOwnerCreated = true;
  await admin.query(`create function ${schema}.fault(kind text) returns void language plpgsql security definer
    set search_path=pg_catalog set session_replication_role=replica as $fault$
    declare changed integer;
    begin
      if session_user<>'openpc_configuration_runtime' or openpc.current_participant_id() is distinct from '${sourceScope.participant}'::uuid
       or openpc.current_privacy_domain_id() is distinct from '${sourceScope.privacy}'::uuid then raise exception 'TEST-SCOPE'; end if;
      if kind in ('corrupt-payload','missing-payload') then
        if kind='corrupt-payload' then
          update control.evidence_segment_payload body set encrypted_segment=body.encrypted_segment||decode('00','hex')
          where body.participant_id='${sourceScope.participant}' and body.privacy_domain_id='${sourceScope.privacy}'
           and exists(select 1 from control.evidence_runtime_artifact_archive a join control.evidence_runtime_artifact_archive_part part
            on part.participant_id=a.participant_id and part.privacy_domain_id=a.privacy_domain_id and part.stream_id=a.stream_id and part.manifest_record_id=a.record_id
            join control.evidence_catalogue c on c.participant_id=part.participant_id and c.privacy_domain_id=part.privacy_domain_id and c.stream_id=part.stream_id and c.record_id=part.record_id
            where a.runtime_configuration_input_id='${original.id}' and c.participant_id=body.participant_id and c.privacy_domain_id=body.privacy_domain_id and c.stream_id=body.stream_id and c.segment_id=body.segment_id);
        else
          delete from control.evidence_segment_payload body where body.participant_id='${sourceScope.participant}' and body.privacy_domain_id='${sourceScope.privacy}'
           and exists(select 1 from control.evidence_runtime_artifact_archive a join control.evidence_runtime_artifact_archive_part part
            on part.participant_id=a.participant_id and part.privacy_domain_id=a.privacy_domain_id and part.stream_id=a.stream_id and part.manifest_record_id=a.record_id
            join control.evidence_catalogue c on c.participant_id=part.participant_id and c.privacy_domain_id=part.privacy_domain_id and c.stream_id=part.stream_id and c.record_id=part.record_id
            where a.runtime_configuration_input_id='${original.id}' and c.participant_id=body.participant_id and c.privacy_domain_id=body.privacy_domain_id and c.stream_id=body.stream_id and c.segment_id=body.segment_id);
        end if;
      elsif kind='wrong-archive' then
        update control.evidence_runtime_artifact_archive set runtime_configuration_input_id='${successor.id}'
         where participant_id='${sourceScope.participant}' and privacy_domain_id='${sourceScope.privacy}' and runtime_configuration_input_id='${original.id}';
      elsif kind='missing-part' then
        delete from control.evidence_runtime_artifact_archive_part part using control.evidence_runtime_artifact_archive a
         where part.participant_id=a.participant_id and part.privacy_domain_id=a.privacy_domain_id and part.stream_id=a.stream_id and part.manifest_record_id=a.record_id
          and a.participant_id='${sourceScope.participant}' and a.privacy_domain_id='${sourceScope.privacy}' and a.runtime_configuration_input_id='${original.id}' and part.ordinal=0;
      else raise exception 'TEST-UNKNOWN-FAULT'; end if;
      get diagnostics changed=row_count;
      if changed not between 1 and 65 then raise exception 'TEST-MISSING-FAULT'; end if;
    end $fault$;
    revoke all on function ${schema}.fault(text) from public;
    grant usage on schema ${schema} to openpc_configuration_runtime;
    grant execute on function ${schema}.fault(text) to openpc_configuration_runtime`);
  const failures = [];
  for (const fault of ['corrupt-payload', 'missing-payload', 'wrong-archive', 'missing-part']) {
    try {
      await scenario(fault, {}, async () => {
        await api.query(`select ${schema}.fault($1)`, [fault]);
        assert.equal(
          (await api.query("select current_setting('session_replication_role') value")).rows[0]
            .value,
          'origin',
        );
        assert.equal((await helper()).rows[0].matches, false);
        await assert.rejects(
          selection(),
          fault === 'wrong-archive'
            ? { code: 'P0002' }
            : { message: 'RUNTIME-DISPOSITION-ARCHIVE_UNPROVEN' },
        );
      });
    } catch (error) {
      failures.push(error);
      process.stderr.write(`OPENPC_SOURCE_SELECTION|FAIL|${fault}\n`);
    }
    // A failed independent fault may continue only after exact original-state
    // readback succeeds. An unsafe restoration blocks the remaining scenarios.
    await scenario(`original-preserved-after-${fault}`, {}, positive);
  }
  if (failures.length) throw new AggregateError(failures, 'Archive integrity regressions failed');
} finally {
  await api.query('rollback');
  if (faultOwnerCreated)
    await admin.query(`drop function if exists ${schema}.fault(text); drop schema ${schema}`);
  api.release();
  await Promise.all([admin.end(), runtime.end(), worker.end()]);
}
