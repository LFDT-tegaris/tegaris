// The original governed source is retired once through the public owner. These
// observations neither seed business state nor supply native/SQL authority.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { sourceScope, verifyRuntimeSourceContainer } from './runtime-source-bootstrap.mjs';
import {
  runtimeArtifactRetirementPlan,
  deleteRuntimeArtifactBatch,
} from '../../../services/control-api/src/evidence/runtime-artifact-deletion-contracts.ts';
import { runtimeArtifactRetirementView } from '../../../services/control-api/src/evidence/runtime-artifact-retirement.ts';
import { runtimeArtifactDispositionView } from '../../../services/control-api/src/evidence/runtime-artifact-disposition-contract.ts';
import { runtimeSourceSigningProfiles } from './runtime-source-disposition-signing.ts';
import { configurationMutationOperation } from '../../../packages/security-kernel/src/configuration-operations.ts';
import { projectApprovalCandidate } from '../../../services/module-registry/src/approval-candidate-contract.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';

const [mode, root, composeText, ...args] = process.argv.slice(2);
const json = async (path) => JSON.parse(await readFile(path, 'utf8'));
const hash = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
function preflight() {
  const [profile] = runtimeSourceSigningProfiles('retirement');
  const operation = configurationMutationOperation(profile.catalogOperationId);
  assert.equal(operation.actionIntentId, 'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1');
  assert.equal(operation.makerCheckerRequired, true);
  assert.equal(operation.stepUpRequired, true);
  assert.equal(operation.aggregateType, 'evidence-deletion');
  assert.deepEqual(
    JSON.parse(profile.definitionCanonicalJson).authority.evidence.map((e) => e.kind),
    [3, 4],
  );
}
preflight();
if (mode === '--preflight') {
  assert.equal(root, undefined);
  process.stdout.write(
    'OPENPC_RUNTIME_RETIREMENT_PREFLIGHT|PASS|exact-profile|independent-governance|native-receipt\n',
  );
} else {
  assert.ok(['plan', 'validate-body', 'effect', 'verify', 'continuation'].includes(mode));
  assert.equal(await realpath(root), root);
  const compose = JSON.parse(composeText);
  assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  const execute = promisify(execFile);
  const run = async (command, argv) =>
    (await execute(command, argv, { timeout: 45000, maxBuffer: 20 * 1024 * 1024 })).stdout;
  const worker = (
    await run(compose[0], [...compose.slice(1), 'ps', '-q', 'control-worker'])
  ).trim();
  const [inspected] = JSON.parse(await run('docker', ['inspect', worker]));
  const config = await json(join(root, 'data/runtime-source-config/configuration.json'));
  const owner = (await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8'))
    .trim()
    .split(':');
  verifyRuntimeSourceContainer(inspected, { root, project: owner[1], config });
  const evidence = join(root, 'evidence/runtime-bootstrap'),
    sourceOutput = join(evidence, 'runtime-source-disposition');
  const output = join(sourceOutput, 'physical-retirement');
  await mkdir(output, { recursive: true, mode: 0o700 });
  const save = (name, value) =>
    writeFile(join(output, `${name}.json`), JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  const original = (await json(join(sourceOutput, 'old-import.json'))).source;
  const sourceAdmission = await json(join(sourceOutput, 'admission.json'));
  const retention = await json(join(sourceOutput, 'retention-recovered.json')).catch(
    async (error) => {
      if (error.code !== 'ENOENT') throw error;
      return json(join(sourceOutput, 'retention.json'));
    },
  );
  const actors = await json(join(evidence, 'deployment-intent-actors.json'));
  const request = async (path, body, expected = 200) => {
    const response = await fetch(`http://127.0.0.1:8080/api/v1/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
        'OpenPC-API-Version': '1',
        'OpenPC-Participant-ID': `urn:openpc:participant:${sourceScope.participant}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${sourceScope.privacy}`,
        'X-Request-ID': original.id,
        'X-Correlation-ID': original.id,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const value = await response.json();
    assert.equal(response.status, expected, `${path}: ${value.code ?? 'unexpected response'}`);
    return value;
  };
  const database = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  const preserved = async () => {
    const {
      rows: [value],
    } = await database.query(
      `select
      (select jsonb_agg(to_jsonb(i)-'configuration_cbor' order by runtime_configuration_input_id)
       from control.runtime_configuration_input i where participant_id=$1 and privacy_domain_id=$2 and runtime_configuration_input_id<>$3) remaining_inputs,
      (select jsonb_agg(to_jsonb(a) order by stream_id,record_id) from control.evidence_runtime_artifact_archive a
       where participant_id=$1 and privacy_domain_id=$2 and runtime_configuration_input_id=$3) archive,
      (select jsonb_agg(to_jsonb(n) order by disposition_id) from control.runtime_artifact_source_denial n
       where participant_id=$1 and privacy_domain_id=$2 and disposition_id=$4) denial`,
      [
        sourceScope.participant,
        sourceScope.privacy,
        original.id,
        sourceAdmission.resourceRef.slice(-36),
      ],
    );
    assert.ok(value.remaining_inputs?.length > 0);
    assert.equal(value.archive?.length, 1);
    assert.equal(value.denial?.length, 1);
    return value;
  };
  const nativeHistory = async () =>
    JSON.parse(
      await run('docker', [
        'exec',
        worker,
        'cat',
        '/runtime-source-journal/owner/runtime-artifact-source.json',
      ]),
    ).history.originals;
  const observation = async () => {
    const admission = await json(join(output, 'admission.json'));
    const {
      rows: [effect],
    } = await database.query(
      `select
      (select count(*)::int from control.runtime_configuration_input where participant_id=$1 and privacy_domain_id=$2 and (runtime_configuration_input_id=$3 or configuration_digest=decode($4,'hex'))) source_rows,
      (select jsonb_agg(to_jsonb(r) order by r.deletion_job_id) from control.runtime_artifact_retirement r where participant_id=$1 and privacy_domain_id=$2 and runtime_configuration_input_id=$3) retirement,
      (select jsonb_agg(to_jsonb(j) order by j.deletion_job_id) from control.deletion_job j where participant_id=$1 and privacy_domain_id=$2 and deletion_job_id=$5 and operation_id=$6) jobs,
      (select count(*)::int from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2 and operation_id=$6 and idempotency_key=$7) operations,
      (select count(*)::int from control.receipt_signing_attempt where participant_id=$1 and privacy_domain_id=$2 and operation_id=$6) attempts,
      (select jsonb_agg(jsonb_build_object('id',receipt_id,'digest',encode(receipt_digest,'hex'),'cbor',encode(receipt_cbor,'hex'),'signature',encode(cose_sign1,'hex')) order by receipt_id) from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and operation_id=$6) receipts,
      (select jsonb_agg(jsonb_build_object('id',event_id,'receipt',receipt_id,'payload',encode(payload_cbor,'hex'),'digest',encode(payload_digest,'hex'),'signature',encode(cose_sign1,'hex')) order by event_id) from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$5 and event_type='io.openpc.control.command.committed.v1' and proof_kind='BUSINESS_RECEIPT_REFERENCE' and sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1') events`,
      [
        sourceScope.participant,
        sourceScope.privacy,
        original.id,
        original.digest.slice(7),
        admission.resourceRef.slice(-36),
        admission.operationId,
        admission.idempotencyKey,
      ],
    );
    assert.equal(effect.source_rows, 0);
    for (const key of ['retirement', 'jobs', 'receipts', 'events'])
      assert.equal(effect[key].length, 1);
    assert.equal(effect.jobs[0].state, 'SUCCEEDED');
    assert.equal(String(effect.jobs[0].deleted_count), '1');
    assert.equal(String(effect.jobs[0].after_used_bytes), '0');
    assert.equal(effect.operations, 1);
    assert.equal(effect.attempts, 1);
    assert.equal(effect.events[0].receipt, effect.receipts[0].id);
    return effect;
  };
  try {
    if (mode === 'plan') {
      const plan = runtimeArtifactRetirementPlan.parse(
        await request('evidence-deletions/runtime-batches/plan', {
          retentionPolicyId: retention.resourceRef,
          previousDeletionJobId: null,
        }),
      );
      assert.equal(plan.eligible, true);
      assert.deepEqual(plan.blockers, []);
      assert.equal(plan.selection.source.runtimeConfigurationInputId, original.id);
      assert.equal(plan.selection.source.configurationDigest, original.digest);
      assert.equal(
        plan.selection.disposition.dispositionId,
        sourceAdmission.resourceRef.slice(-36),
      );
      await save('preserved-before', {
        database: await preserved(),
        history: await nativeHistory(),
      });
      await save('plan', plan);
    } else if (mode === 'validate-body') {
      const body = deleteRuntimeArtifactBatch.parse(JSON.parse(args[0]));
      assert.equal(body.selection.source.runtimeConfigurationInputId, original.id);
      assert.deepEqual(body.selection, (await json(join(output, 'plan.json'))).selection);
      const operation = configurationMutationOperation('CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH');
      assert.deepEqual(
        projectApprovalCandidate({
          document: body,
          candidateDigest: sha256(body),
          catalogOperationId: operation.catalogOperationId,
          actionIntentId: operation.actionIntentId,
          resourceType: operation.resourceType,
          operationClass: operation.operationClass,
        }),
        { candidate: body, redactedFields: [] },
      );
    } else if (mode === 'effect') {
      const [phase] = args;
      assert.ok(['before-replay', 'after-replay'].includes(phase));
      const effect = await observation();
      if (phase === 'after-replay')
        assert.deepEqual(effect, await json(join(output, 'before-replay.json')));
      await save(phase, effect);
    } else if (mode === 'continuation') {
      const admission = await json(join(output, 'admission.json'));
      const continued = runtimeArtifactRetirementPlan.parse(
        await request('evidence-deletions/runtime-batches/plan', {
          retentionPolicyId: retention.resourceRef,
          previousDeletionJobId: admission.resourceRef,
        }),
      );
      assert.equal(continued.eligible, false);
      assert.equal(continued.continuationState, 'BLOCKED');
      assert.ok(continued.blockers.includes('GOVERNED_DISPOSITION_REQUIRED'));
      const bypass = runtimeArtifactRetirementPlan.parse(
        await request('evidence-deletions/runtime-batches/plan', {
          retentionPolicyId: retention.resourceRef,
          previousDeletionJobId: null,
        }),
      );
      assert.equal(bypass.eligible, false);
      assert.deepEqual(bypass.blockers, ['STALE_SELECTION']);
      await save('continuation', { continued, bypass });
    } else {
      const [phase] = args;
      assert.ok(['native', 'restart'].includes(phase));
      const admission = await json(join(output, 'admission.json'));
      const proof = runtimeArtifactRetirementView.parse(
        await request(
          `evidence-deletions/${encodeURIComponent(admission.resourceRef)}/runtime-retirement`,
        ),
      );
      assert.equal(proof.retirement.source.runtimeConfigurationInputId, original.id);
      const view = runtimeArtifactDispositionView.parse(
        await request(
          `evidence-deletions/runtime-sources/${encodeURIComponent(sourceAdmission.resourceRef)}`,
        ),
      );
      assert.equal(view.physicalState, 'RETIRED');
      assert.equal(view.nativeState, 'DENIED');
      let originalRecord;
      for (let n = 0; n < 120; n++) {
        const records = (await nativeHistory()).filter(
          (wire) =>
            JSON.parse(Buffer.from(wire).toString()).claims.observation.RetirementCommitted?.input
              .input_id === original.id,
        );
        if (records.length) {
          assert.equal(records.length, 1);
          originalRecord = records[0];
          break;
        }
        assert.notEqual(n, 119, 'Native retirement was not reconciled');
        await delay(250);
      }
      const committed = JSON.parse(Buffer.from(originalRecord).toString()).claims.observation
        .RetirementCommitted;
      assert.equal(committed.deletion_job_id, admission.resourceRef.slice(-36));
      assert.equal(committed.operation_id, admission.operationId);
      const effect = await observation();
      const baseline = await json(join(output, 'preserved-before.json'));
      assert.deepEqual(await preserved(), baseline.database);
      assert.deepEqual((await nativeHistory()).slice(0, baseline.history.length), baseline.history);
      assert.equal(`sha256:${committed.receipt_digest}`, proof.receipt.receiptDigest);
      assert.equal(
        hash(Buffer.from(effect.receipts[0].signature, 'hex')),
        proof.receipt.coseDigest,
      );
      const result = { proof, view, originalRecord, effect };
      if (phase === 'restart') assert.deepEqual(result, await json(join(output, 'native.json')));
      await save(phase, result);
    }
    process.stdout.write(
      `OPENPC_RUNTIME_RETIREMENT|PASS|${mode}|${args[0] && ['effect', 'verify'].includes(mode) ? args[0] : 'original'}\n`,
    );
  } finally {
    await database.end();
  }
}
