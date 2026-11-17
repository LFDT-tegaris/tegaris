import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { tsImport } from 'tsx/esm/api';
import { withProviderReadbackRollback } from './provider-probe-readback-transaction.mjs';
const {
  parseProviderRetryProbeReference,
  readProviderRetryProbeOriginal,
  withCurrentProviderRetryProbeSource,
} = await tsImport(
  '../../../services/control-api/src/configuration/operations/provider-retry-probe-source.ts',
  import.meta.url,
);
const [secrets, data, providerId, originalOperationId, mode = 'current', expectedRevision] =
  process.argv.slice(2);
if (!secrets || !data || !providerId)
  throw new Error('Owned provider observation context required');
if (!['current', 'historical'].includes(mode) || (mode === 'historical' && !originalOperationId))
  throw new Error('Historical readback requires the original qualification operation');
if (
  expectedRevision !== undefined &&
  (mode !== 'current' || !/^[1-9][0-9]*$/u.test(expectedRevision))
)
  throw new Error('A public revision can bind only current native source readback');
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secrets, 'control_pg_password.txt'), 'utf8')).trim(),
});

try {
  const { rows } = await pool.query(
    `select o.*,p.state provider_state,p.revision provider_revision,
    w.configuration_work_id,w.operation_id,w.result_receipt,w.result_receipt_digest,w.result_event_id,w.state work_state,
    'sha256:'||encode(a.evidence_digest,'hex') authorization_evidence_digest
    from control.provider_profile p
    join control.configuration_work w on w.resource_id=p.provider_profile_id
      and w.participant_id=p.participant_id and w.privacy_domain_id=p.privacy_domain_id
      and w.work_kind='PROVIDER_QUALIFICATION' and w.state in ('COMPLETED','FAILED')
    join control.mutation_evidence a on a.operation_id=w.operation_id
      and a.participant_id=w.participant_id and a.privacy_domain_id=w.privacy_domain_id
    join control.provider_probe_observation o on o.provider_profile_id=p.provider_profile_id
      and o.participant_id=w.participant_id and o.privacy_domain_id=w.privacy_domain_id
      and o.observed_revision=a.aggregate_version-1
      and o.input_digest=w.input_digest and o.configuration_digest=w.configuration_digest
    where p.provider_profile_id=$1 and ($2::uuid is null or w.operation_id=$2::uuid)`,
    [providerId, originalOperationId ?? null],
  );
  assert.equal(
    rows.length,
    1,
    'exact original qualification lineage is required; ambiguous or missing originals are blocked',
  );
  const row = rows[0];
  if (expectedRevision !== undefined)
    assert.equal(
      String(row.provider_revision),
      expectedRevision,
      'public revision must match the original native source',
    );
  const reference = parseProviderRetryProbeReference({
    providerProfileId: providerId,
    observationId: row.observation_id,
    qualificationWorkId: row.configuration_work_id,
    operationId: row.operation_id,
    resultEventId: row.result_event_id,
    artifactDigest: row.input_digest,
    configurationDigest: row.configuration_digest,
    observationDigest: row.observation_digest,
    resultReceiptDigest: row.result_receipt_digest,
    authorizationEvidenceDigest: row.authorization_evidence_digest,
  });
  const scope = {
    participantId: row.participant_id,
    privacyDomainId: row.privacy_domain_id,
    requestId: (await pool.query('select uuidv7()::text id')).rows[0].id,
  };
  const requestLog = join(data, 'rpc-provider', 'requests.jsonl');
  const beforeRequests = await readFile(requestLog, 'utf8');
  await withProviderReadbackRollback(
    pool,
    async (sourceClient) => {
      await sourceClient.query('begin isolation level read committed');
      await sourceClient.query('set local role openpc_control_owner');
      await sourceClient.query('set local row_security=on');
      await sourceClient.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        [scope.participantId, scope.privacyDomainId, scope.requestId],
      );
      const original = await readProviderRetryProbeOriginal(sourceClient, scope, reference);
      assert.equal(original.workState, row.work_state);
      assert.deepEqual(original.observation, row.observation);
      assert.deepEqual(original.resultReceipt, row.result_receipt);
      if (mode === 'current') {
        await withCurrentProviderRetryProbeSource(
          sourceClient,
          scope,
          reference,
          async (sameClient, current) => {
            assert.equal(sameClient, sourceClient);
            assert.deepEqual(current, original);
            assert.equal(current.workState, 'COMPLETED');
            assert.ok(Object.isFrozen(current.observation));
          },
        );
      }
    },
    { retryContention: true },
  );
  assert.equal(
    await readFile(requestLog, 'utf8'),
    beforeRequests,
    'source readback performs no provider I/O',
  );
  assert.equal(row.state, 'OBSERVED');
  assert.equal(BigInt(row.observed_revision), BigInt(row.source_revision) + 1n);
  if (mode === 'current') {
    assert.equal(BigInt(row.provider_revision), BigInt(row.observed_revision) + 2n);
    assert.ok(['QUALIFIED', 'ACTIVE'].includes(row.provider_state));
  }
  if (row.work_state === 'COMPLETED') {
    assert.equal(row.result_receipt.liveObservationId, row.observation_id);
    assert.equal(row.result_receipt.liveObservationDigest, row.observation_digest);
    assert.deepEqual(row.result_receipt.liveObservation, row.observation);
  }
  assert.equal(row.observation.exchanges.length, 18);
  const requests = beforeRequests.trim().split('\n').map(JSON.parse);
  if (mode === 'current' && !originalOperationId) {
    assert.equal(requests.length, 18, 'actual mTLS provider received the whole two-round corpus');
    assert.equal(requests.filter((r) => r.method === 'eth_call').length, 6);
  }
  const text = JSON.stringify(row.observation);
  for (const restricted of [
    'https://',
    'PRIVATE KEY',
    'controlled-provider/v1',
    '0x01020304',
    '0x1234',
  ])
    assert.ok(!text.includes(restricted), 'only safe observation metadata is durable');
  await withProviderReadbackRollback(pool, async (client) => {
    await client.query('begin');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)",
      [row.participant_id, row.privacy_domain_id],
    );
    await assert.rejects(
      client.query(
        "update control.provider_probe_observation set observation='{}' where observation_id=$1",
        [row.observation_id],
      ),
      (error) => error.code === 'P0001' && error.message === 'DATA-6020-IMMUTABLE-ROW',
    );
    await client.query('rollback');
    await client.query('begin');
    await client.query('set local role openpc_control_runtime');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)",
      [row.participant_id, row.privacy_domain_id],
    );
    await assert.rejects(
      client.query(
        'update control.provider_probe_observation set state=state where observation_id=$1',
        [row.observation_id],
      ),
      (error) => error.code === '42501',
      'API role cannot mint or rewrite runtime observations',
    );
    await client.query('rollback');
    await client.query('begin');
    await client.query('set local role openpc_control_reader');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)",
      [row.participant_id, '018f0000-0000-7000-8000-000000000299'],
    );
    assert.equal(
      (
        await client.query(
          'select 1 from control.provider_probe_observation where observation_id=$1',
          [row.observation_id],
        )
      ).rowCount,
      0,
    );
  });
  process.stdout.write(
    mode === 'current' && !originalOperationId
      ? 'OPENPC_PROVIDER_LIVE_OBSERVATION|PASS|real-mtls|18-exchanges|reviewed-revision|immutable-evidence|privacy-isolation|same-client-source-fence\n'
      : `OPENPC_PROVIDER_ORIGINAL_READBACK|PASS|${mode}|original-lineage|immutable-evidence|privacy-isolation|zero-provider-io\n`,
  );
} finally {
  await pool.end();
}
