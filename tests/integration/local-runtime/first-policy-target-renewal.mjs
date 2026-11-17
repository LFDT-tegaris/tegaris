import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';

const execute = promisify(execFile);

export async function refreshFirstPolicyAuthority({
  secretRoot,
  evidenceRoot,
  privacyDomainId,
  targetId,
  journey = 'first-policy',
}) {
  const tls = join(evidenceRoot, '../../data/runtime-bootstrap/runtime/tls');
  const output = join(evidenceRoot, `${journey}-workload-identity.json`);
  await writeFile(output, '', { mode: 0o600 });
  const { stdout } = await execute(
    'curl',
    [
      '--silent',
      '--show-error',
      '--max-time',
      '10',
      '--tlsv1.3',
      '--tls-max',
      '1.3',
      '--cacert',
      join(secretRoot, 'identity_mtls_ca.pem'),
      '--cert',
      join(tls, 'ads-client.pem'),
      '--key',
      join(tls, 'ads-client.key'),
      '-H',
      'Content-Type: application/json',
      '--data',
      JSON.stringify({
        runtimeContext: {
          privacyDomainId: privacyDomainId,
          targetRuntimeId: targetId,
        },
      }),
      '-o',
      output,
      '-w',
      '%{http_code}',
      'https://127.0.0.1:53443/internal/v1/workload/authenticate',
    ],
    { timeout: 12000 },
  );
  assert.equal(stdout, '200', 'actual target mTLS authentication must pass');
  const value = JSON.parse(await readFile(output, 'utf8'));
  assert.equal(value.workloadId, `urn:openpc:workload:${targetId}`);
  assert.ok(value.runtime?.snapshotId);
  assert.ok(BigInt(value.runtime.expiresAtNs) > BigInt(Date.now() + 20000) * 1000000n);
  return value.runtime.snapshotId;
}

// Host-side input reads only. Public mutations and checkpoint persistence stay
// outside this retry boundary; their original effects are never replayed here.
export async function prepareTargetRenewalInputs(pool, scope, prepare) {
  const discovery = async (client) =>
    (
      await client.query(
        'select openpc.runtime_target_discovery_current($1::uuid,$2::uuid,$3::uuid) current',
        [scope.participantId, scope.privacyDomainId, scope.targetId],
      )
    ).rows[0]?.current === true;
  const snapshot = async (serializable, read) => {
    const client = await pool.connect();
    try {
      await client.query(serializable ? 'begin isolation level serializable' : 'begin');
      await client.query('set local role openpc_control_reader');
      await client.query('set local row_security=on');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1::uuid,$2::uuid,uuidv7(),'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',false)",
        [scope.participantId, scope.privacyDomainId],
      );
      return await read(client);
    } finally {
      try {
        await client.query('rollback');
      } finally {
        client.release();
      }
    }
  };
  // Each observation owns a fresh snapshot: a future discovery lease cannot
  // appear inside an already established SERIALIZABLE transaction.
  await expect.poll(() => snapshot(false, discovery), { timeout: 10000 }).toBe(true);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await snapshot(true, async (client) => {
        assert.equal(await discovery(client), true, 'Current discovery required at preparation');
        return prepare(client);
      });
    } catch (error) {
      if (!['40001', '40P01'].includes(error?.code) || attempt === 2) throw error;
    }
    await delay(10 * 3 ** attempt);
  }
}

// Fixture readback only: this does not authorize a successor. The public
// target owner still independently checks current source/revision/authority.
export async function readTerminalRenewalFailure(client, targetId, prior) {
  const result = await client.query(
    `select w.configuration_work_id::text as "workId",w.operation_id::text as "operationId",
     w.runtime_configuration_generation_id::text as "generationId",
     w.state,w.attempt_count::text as "attemptCount",w.execution_attempt_id::text as "executionAttemptId",
     w.execution_started_at::text as "executionStartedAt",w.result_event_id::text as "resultEventId",
     w.result_receipt_digest as "resultReceiptDigest",w.last_error_code as "errorCode",
     t.revision::text as "targetRevision",
     (select count(*)::int from control.runtime_activation_observation o
      where o.configuration_work_id=w.configuration_work_id) as "observationCount",
     (select count(*)::int from control.runtime_target_disposition_admission a
      where a.runtime_target_id=t.runtime_target_id and a.binding->'cause'->>'work_id'=w.configuration_work_id::text) as "admissionCount"
     from control.configuration_work w join control.runtime_target t
      on t.runtime_target_id=w.runtime_target_id and t.participant_id=w.participant_id
      and t.privacy_domain_id=w.privacy_domain_id
     join control.idempotency_record i on i.operation_id=w.operation_id and i.idempotency_key=$3
      and i.participant_id=w.participant_id and i.result_payload is not null
     where w.operation_id=$1::uuid and w.runtime_target_id=$2::uuid
      and w.work_kind='RUNTIME_ACTIVATION' and t.state='FAILED'`,
    [prior.operation.operationId, targetId, prior.key],
  );
  assert.equal(result.rowCount, 1, 'Exact original failed renewal required');
  return result.rows[0];
}

export function preserveTerminalRenewal(checkpoint, before, operation, failure, selected) {
  const prior = checkpoint.targetRenewal;
  assert.match(
    selected ?? '',
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  assert.ok(prior && !prior.target);
  assert.equal(prior.operation.operationId, selected);
  assert.equal(operation.operationId, selected);
  assert.equal(operation.state, 'FAILED');
  assert.equal(operation.truthState, 'FAILED');
  assert.equal(before.state, 'FAILED');
  assert.equal(failure.operationId, selected);
  assert.equal(failure.state, 'FAILED');
  assert.equal(failure.targetRevision, before.revision);
  assert.ok(BigInt(before.revision) > BigInt(prior.operation.revision));
  assert.match(failure.attemptCount ?? '', /^[1-9][0-9]{0,19}$/u);
  assert.ok(BigInt(failure.attemptCount) <= 18446744073709551615n);
  assert.equal(failure.executionAttemptId, null);
  assert.equal(failure.executionStartedAt, null);
  assert.equal(failure.observationCount, 0);
  assert.equal(failure.admissionCount, 0);
  for (const field of ['workId', 'resultEventId'])
    assert.match(
      failure[field] ?? '',
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
  assert.match(failure.resultReceiptDigest ?? '', /^sha256:[0-9a-f]{64}$/u);
  assert.ok(
    !(checkpoint.priorTargetRenewals ?? []).some((v) => v.operation.operationId === selected),
  );
  checkpoint.priorTargetRenewals ??= [];
  checkpoint.priorTargetRenewals.push({ ...prior, failure: structuredClone(failure) });
  delete checkpoint.targetRenewal;
}

// A recovered expired activation is historical custody. Renew unchanged
// policy through the existing target owner before claiming current serving.
export async function submitFirstPolicyTargetRenewal({
  input,
  targetId,
  checkpoint,
  publicRead,
  persist,
  connect,
  refresh,
  secretRoot,
  evidenceRoot,
  priorAuthorityExpiresAtNs,
  failedRenewalSuccessorOf,
  beforeSubmit = async () => {},
}) {
  await expect
    .poll(
      async () =>
        (
          await publicRead(
            `/api/v1/activation-occurrences/urn:openpc:resource:${checkpoint.references.occurrenceId}`,
          )
        ).state,
      { timeout: 30000 },
    )
    .toBe('ACTIVE_MATCHED');
  const targetPath = `/api/v1/runtime-targets/urn:openpc:resource:${targetId}`;
  const before = await publicRead(targetPath);
  assert.ok(before.activeGenerationDigest);
  checkpoint.originalActivationHistoricalOnly = true;
  if (checkpoint.targetRenewal?.target && priorAuthorityExpiresAtNs) {
    assert.ok(BigInt(priorAuthorityExpiresAtNs) <= BigInt(Date.now()) * 1000000n);
    const prior = checkpoint.targetRenewal;
    assert.equal(
      (await publicRead(`/api/v1/operations/${prior.operation.operationId}`)).state,
      'SUCCEEDED',
    );
    assert.equal(before.activeGenerationDigest, prior.target.activeGenerationDigest);
    assert.equal(before.revision, prior.target.revision);
    checkpoint.priorTargetRenewals ??= [];
    checkpoint.priorTargetRenewals.push(prior);
    delete checkpoint.targetRenewal;
    await persist();
  }
  await connect();
  {
    const pool = new Pool({
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_source_control_reader',
      password: (await readFile(join(secretRoot, 'source_control_db_password.txt'), 'utf8')).trim(),
      max: 1,
    });
    try {
      const original = failedRenewalSuccessorOf
        ? checkpoint.priorTargetRenewals?.find(
            (value) => value.operation.operationId === failedRenewalSuccessorOf,
          )
        : undefined;
      if (original) {
        assert.ok(original.failure, 'Only the explicitly selected terminal failure may resume');
        if (checkpoint.targetRenewal)
          assert.equal(checkpoint.targetRenewal.successorOf, failedRenewalSuccessorOf);
      }
      const terminal = failedRenewalSuccessorOf && !original ? checkpoint.targetRenewal : undefined;
      if (terminal) assert.equal(terminal.operation?.operationId, failedRenewalSuccessorOf);
      if (failedRenewalSuccessorOf && !original) assert.ok(terminal);
      const prepared = await prepareTargetRenewalInputs(
        pool,
        { ...input, targetId },
        async (client) => {
          const failure = terminal
            ? await readTerminalRenewalFailure(client, targetId, terminal)
            : undefined;
          if (checkpoint.targetRenewal && !terminal) return { failure };
          const candidate = await client.query(
            `select 'sha256:'||encode(sha256(configuration.configuration_digest||policy.generation_digest||
          convert_to(provider.behavior_fingerprint,'UTF8')||convert_to(projection.plan_digest,'UTF8')||
          convert_to(target.runtime_target_id::text,'UTF8')),'hex') digest
         from control.runtime_target target
         join control.module_installation installation on installation.participant_id=target.participant_id
          and installation.privacy_domain_id=target.privacy_domain_id and installation.state='ENABLED'
         join control.module_version version on version.module_version_id=installation.module_version_id
          and version.module_id='pc.config.assets'
         join control.runtime_configuration_input_current_metadata configuration on configuration.module_installation_id=installation.module_installation_id and configuration.active
         join control.policy_generation policy on policy.participant_id=target.participant_id and policy.privacy_domain_id=target.privacy_domain_id and policy.state='ACTIVE' and policy.active
         join control.provider_profile provider on provider.participant_id=target.participant_id and provider.privacy_domain_id=target.privacy_domain_id and provider.state in ('QUALIFIED','ACTIVE')
         join control.projection_plan projection on projection.participant_id=target.participant_id and projection.privacy_domain_id=target.privacy_domain_id and projection.state in ('VALIDATED','RUNNING') and projection.readiness='READY'
         where target.runtime_target_id=$1 and target.participant_id=$2 and target.privacy_domain_id=$3`,
            [targetId, input.participantId, input.privacyDomainId],
          );
          assert.equal(candidate.rowCount, 1);
          const actionIntentId = 'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1';
          const action = await client.query(
            "select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id=$1",
            [actionIntentId],
          );
          assert.equal(action.rowCount, 1);
          return {
            failure,
            candidateDigest: candidate.rows[0].digest,
            actionDigest: action.rows[0].digest,
          };
        },
      );
      // Only successful, rolled-back/released input reads may update the
      // continuation. Public terminal readback is also outside the retry loop.
      if (prepared.failure) {
        const operation = await publicRead(`/api/v1/operations/${failedRenewalSuccessorOf}`);
        preserveTerminalRenewal(
          checkpoint,
          before,
          operation,
          prepared.failure,
          failedRenewalSuccessorOf,
        );
      }
      if (!checkpoint.targetRenewal) {
        assert.ok(prepared.candidateDigest && prepared.actionDigest);
        checkpoint.targetRenewal = {
          before,
          ...(failedRenewalSuccessorOf ? { successorOf: failedRenewalSuccessorOf } : {}),
          key: `first-policy-runtime-renewal-${targetId}-${before.revision}`,
          etag: `"${sha256({ resourceId: targetId, revision: before.revision })}"`,
          body: {
            actionIntentId: 'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
            actionIntentDigest: prepared.actionDigest,
            expectedRevision: before.revision,
            replacementDigest: prepared.candidateDigest,
            reason: failedRenewalSuccessorOf
              ? `Request a separately governed current renewal after terminal no-execution operation ${failedRenewalSuccessorOf}; preserve its failure and original activation.`
              : 'Renew unchanged first-policy custody after historical activation recovery.',
          },
        };
        await persist();
      }
    } finally {
      await pool.end();
    }
  }
  const renewal = checkpoint.targetRenewal;
  if (!renewal.operation) {
    const { responseIds } = await import('../../../apps/admin-web/app/api/v1/ui/local-runtime.ts');
    const actors = JSON.parse(
      await readFile(join(evidenceRoot, 'deployment-intent-actors.json'), 'utf8'),
    );
    const origin = 'http://127.0.0.1:8080';
    const ids = responseIds();
    const headers = {
      'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
      'Content-Type': 'application/json',
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': `urn:openpc:participant:${input.participantId}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${input.privacyDomainId}`,
      'X-Request-ID': ids.requestId,
      'X-Correlation-ID': ids.correlationId,
      'Origin': origin,
    };
    const csrf = await fetch(`${origin}/api/v1/session/csrf`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ actionIntentId: renewal.body.actionIntentId }),
      signal: AbortSignal.timeout(10000),
    });
    assert.equal(csrf.status, 200);
    const csrfToken = (await csrf.json()).csrfToken;
    await beforeSubmit();
    await refresh();
    const response = await fetch(`${origin}${targetPath}`, {
      method: 'PATCH',
      headers: {
        ...headers,
        'X-CSRF-Token': csrfToken,
        'Idempotency-Key': renewal.key,
        'OpenPC-Action-Intent-Digest': renewal.body.actionIntentDigest,
        'If-Match': renewal.etag,
      },
      body: JSON.stringify(renewal.body),
      signal: AbortSignal.timeout(15000),
    });
    const body = await response.json();
    assert.equal(response.status, 202, JSON.stringify(body));
    renewal.operation = body;
    await persist();
  }
  return renewal;
}

export async function renewFirstPolicyTarget(options) {
  const { observe, publicRead, targetId, persist } = options;
  const renewal = await submitFirstPolicyTargetRenewal(options);
  await observe();
  await expect
    .poll(
      async () => (await publicRead(`/api/v1/operations/${renewal.operation.operationId}`)).state,
      { timeout: 30000 },
    )
    .toBe('SUCCEEDED');
  const target = await publicRead(`/api/v1/runtime-targets/urn:openpc:resource:${targetId}`);
  assert.equal(target.state, 'ACTIVE_MATCHED');
  assert.equal(target.activeGenerationDigest, target.desiredGenerationDigest);
  assert.notEqual(target.activeGenerationDigest, renewal.before.activeGenerationDigest);
  assert.notEqual(target.xdsVersionDigest, renewal.before.xdsVersionDigest);
  assert.ok(BigInt(target.revision) > BigInt(renewal.before.revision));
  renewal.target = target;
  await persist();
  process.stdout.write(
    'OPENPC_FIRST_POLICY_RENEWAL|PASS|historical-original-preserved|public-target-owner|fresh-mTLS-authority|new-capsule|actual-request-observation\n',
  );
}
