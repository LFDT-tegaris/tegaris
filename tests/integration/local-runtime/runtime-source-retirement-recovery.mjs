import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import { withTransactionBrowser, readWorkbenchApproval } from './transaction-workbench-browser.mjs';
import { sourceScope } from './runtime-source-bootstrap.mjs';
import { projectApprovalCandidate } from '../../../services/module-registry/src/approval-candidate-contract.ts';
import { transactionOperation } from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { mutationResumeGuardsSql } from '../../../services/identity-service/src/db/mutation-resume-guards.mjs';
import {
  readRuntimeRetirementApprovalChain,
  requireNewRetirementObservation,
} from './runtime-source-retirement-recovery-state.mjs';

// Existing public intent only. SQL observes it and tests the installed no-effect
// fence; all successor approval, independent decision and execution are public.
const [mode, root, composeText] = process.argv.slice(2);
assert.ok(['prepared', 'preflight', 'resume', 'committed'].includes(mode));
if (mode === 'resume') assert.deepEqual(JSON.parse(composeText).slice(0, 2), ['docker', 'compose']);
const evidence = join(root, 'evidence/runtime-bootstrap');
const output = join(evidence, 'runtime-source-disposition/physical-retirement');
const json = async (name) => JSON.parse(await readFile(join(output, `${name}.json`), 'utf8'));
const save = (name, value) =>
  writeFile(join(output, `${name}.json`), JSON.stringify(value), {
    flag: 'wx',
    mode: 0o600,
  });
const requireNewObservation = (name) => requireNewRetirementObservation(output, name);
const originalApproval = (await json('admission-approval')).resourceRef.slice(-36);
const proposal = await json('admission-proposal');
const plan = await json('plan');
const pool = async (user, secret) =>
  new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user,
    password: (await readFile(join(root, 'secrets', secret), 'utf8')).trim(),
    max: 2,
    statement_timeout: 5000,
    query_timeout: 7000,
  });
const admin = await pool('openpc_control', 'control_pg_password.txt');
const runtime = await pool('openpc_configuration_runtime', 'control_api_runtime_db_password.txt');
const probeSchema = `openpc_retirement_probe_${randomBytes(8).toString('hex')}`;
let probeCreated = false;
try {
  const selected = await admin.query(
    `select c.* from control.mutation_candidate c
    join control.approval_request a on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
      and a.subject_id=c.mutation_candidate_id where a.participant_id=$1 and a.privacy_domain_id=$2 and a.approval_request_id=$3`,
    [sourceScope.participant, sourceScope.privacy, originalApproval],
  );
  assert.equal(selected.rowCount, 1);
  const candidate = selected.rows[0];
  const operation = transactionOperation('evidence-deletion-runtime');
  const body = operation.input.parse(candidate.candidate_document);
  assert.equal(candidate.catalog_operation_id, 'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH');
  assert.equal(candidate.action_intent_id, operation.actionIntentId);
  assert.equal(body.actionIntentDigest, operation.actionIntentDigest);
  assert.equal(candidate.idempotency_key, 'runtime-source-retirement-0001');
  assert.equal(`urn:openpc:resource:${candidate.resource_id}`, proposal.resourceRef);
  assert.equal(sha256(body), proposal.candidateDigest);
  assert.equal(`sha256:${candidate.candidate_digest.toString('hex')}`, proposal.candidateDigest);
  assert.deepEqual(body.selection, plan.selection);
  assert.equal(body.beforeDigest, plan.beforeDigest);
  assert.deepEqual(
    projectApprovalCandidate({
      document: body,
      candidateDigest: proposal.candidateDigest,
      catalogOperationId: candidate.catalog_operation_id,
      actionIntentId: candidate.action_intent_id,
      resourceType: candidate.resource_type,
      operationClass: candidate.operation_class,
    }),
    { candidate: body, redactedFields: [] },
  );
  const functionName =
    mode === 'prepared'
      ? `${probeSchema}.prepared_retirement_resume`
      : 'openpc.assert_mutation_resume_no_effect';
  if (mode !== 'committed') {
    // Isolated predicate faults only. Preserve the product login's lack of DDL
    // and TEMP privileges; all fixture objects have one random owned schema.
    await admin.query(`create schema ${probeSchema}`);
    probeCreated = true;
    await admin.query(`grant usage on schema ${probeSchema} to openpc_configuration_runtime`);
    if (mode === 'prepared') {
      await admin.query(
        mutationResumeGuardsSql
          .slice(0, mutationResumeGuardsSql.indexOf('END $$;') + 7)
          .replace('openpc.assert_mutation_resume_no_effect(', `${functionName}(`),
      );
      await admin.query(`revoke all on function ${functionName}(uuid) from public`);
      await admin.query(
        `grant execute on function ${functionName}(uuid) to openpc_configuration_runtime`,
      );
    }
    const definition = (
      await admin.query('select pg_get_functiondef($1::regprocedure) definition', [
        `${functionName}(uuid)`,
      ])
    ).rows[0].definition;
    const copiedTables = {
      mutation_candidate: '*',
      runtime_artifact_retirement:
        'participant_id,privacy_domain_id,deletion_job_id,runtime_configuration_input_id,configuration_digest',
      deletion_job: 'participant_id,privacy_domain_id,deletion_job_id,target_data_class,selection',
      idempotency_record:
        'participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,operation_id,terminal_state',
      receipt_signing_attempt: 'participant_id,privacy_domain_id,profile_digest,operation_id',
      audit_occurrence: 'participant_id,privacy_domain_id,aggregate_id,candidate_digest',
      mutation_evidence:
        'participant_id,privacy_domain_id,aggregate_id,catalog_operation_id,candidate_digest',
      outbox_event: 'participant_id,privacy_domain_id,aggregate_id',
    };
    let isolated = definition.replace(
      /CREATE OR REPLACE FUNCTION [^\n]+\(/u,
      `CREATE OR REPLACE FUNCTION ${probeSchema}.retirement_resume_fault(`,
    );
    for (const [table, columns] of Object.entries(copiedTables)) {
      await admin.query(
        `create table ${probeSchema}.${table} as select ${columns} from control.${table} where false`,
      );
      await admin.query(
        `grant select,insert,update on ${probeSchema}.${table} to openpc_configuration_runtime`,
      );
      isolated = isolated.replaceAll(`control.${table}`, `${probeSchema}.${table}`);
    }
    await admin.query(
      `insert into ${probeSchema}.mutation_candidate select * from control.mutation_candidate where mutation_candidate_id=$1`,
      [candidate.mutation_candidate_id],
    );
    await admin.query(isolated);
    await admin.query(
      `revoke all on function ${probeSchema}.retirement_resume_fault(uuid) from public`,
    );
    await admin.query(
      `grant execute on function ${probeSchema}.retirement_resume_fault(uuid) to openpc_configuration_runtime`,
    );
  }
  const client = await runtime.connect(),
    other = await runtime.connect();
  const begin = async (
    connection,
    privacy = sourceScope.privacy,
    action = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
  ) => {
    await connection.query('begin isolation level serializable');
    await connection.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
      sourceScope.participant,
      privacy,
      id(),
      action,
    ]);
  };
  const proof = () => client.query(`select ${functionName}($1)`, [candidate.mutation_candidate_id]);
  try {
    await begin(client);
    if (mode === 'committed') {
      await assert.rejects(proof(), { code: 'P0001', message: 'PC-POLICY-2004' });
      await client.query('rollback');
      process.stdout.write(
        'OPENPC_RUNTIME_RETIREMENT_RECOVERY|PASS|consumed-original-cannot-renew\n',
      );
    } else {
      assert.equal(candidate.consumed_operation_id, null);
      await proof();
      await client.query('rollback');
      await begin(client, id());
      await assert.rejects(proof(), { code: 'P0002' });
      await client.query('rollback');
      await begin(client);
      await assert.rejects(
        client.query('select configuration_cbor from control.runtime_configuration_input limit 1'),
        { code: '42501' },
      );
      await client.query('rollback');

      // Physical execution's first producer fence excludes renewal before any
      // successor state. Conversely renewal holds that fence until rollback.
      await begin(other, sourceScope.privacy, operation.actionIntentId);
      await other.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
        `evidence-lifecycle:${sourceScope.participant}`,
      ]);
      await begin(client);
      await assert.rejects(proof(), { code: 'P0001', message: 'PC-POLICY-2004' });
      await assert.rejects(client.query('select 1'), { code: '25P02' });
      await client.query('rollback');
      await other.query('rollback');
      await begin(client);
      await proof();
      await begin(other, sourceScope.privacy, operation.actionIntentId);
      assert.equal(
        (
          await other.query('select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired', [
            `evidence-lifecycle:${sourceScope.participant}`,
          ])
        ).rows[0].acquired,
        false,
      );
      await other.query('rollback');
      await client.query('rollback');
      await begin(client);
      const faultProof = () =>
        client.query(`select ${probeSchema}.retirement_resume_fault($1)`, [
          candidate.mutation_candidate_id,
        ]);
      await faultProof();
      const fault = async (apply) => {
        await client.query('savepoint fault');
        await apply();
        await assert.rejects(faultProof(), { code: 'P0001', message: 'PC-POLICY-2004' });
        await client.query('rollback to savepoint fault');
      };
      for (const [field, value] of [
        ['configurationBytes', body.selection.source.configurationBytes + 1],
        ['runtimeConfigurationInputId', id()],
        ['moduleInstallationId', id()],
        ['moduleConfigurationGenerationId', id()],
        ['configurationDigest', sha256('alias')],
        ['resourceBindingsDigest', sha256('other bindings')],
        ['createdAt', '2000-01-01T00:00:00.000000Z'],
      ]) {
        const changed = structuredClone(body);
        changed.selection.source[field] = value;
        await fault(() =>
          client.query(
            `update ${probeSchema}.mutation_candidate set candidate_document=$1,candidate_digest=$2`,
            [changed, Buffer.from(sha256(changed).slice(7), 'hex')],
          ),
        );
      }
      await fault(() =>
        client.query(
          `update ${probeSchema}.mutation_candidate set state='CONSUMED',consumed_operation_id=$1`,
          [id()],
        ),
      );
      const scope = [sourceScope.participant, sourceScope.privacy];
      for (const [input, digest, job] of [
        [body.selection.source.runtimeConfigurationInputId, sha256('other'), id()],
        [id(), body.selection.source.configurationDigest, id()],
        [id(), sha256('other'), candidate.resource_id],
      ]) {
        await fault(() =>
          client.query(
            `insert into ${probeSchema}.runtime_artifact_retirement values($1,$2,$3,$4,$5)`,
            [...scope, job, input, digest],
          ),
        );
        const selection = {
          ...body.selection,
          source: {
            ...body.selection.source,
            runtimeConfigurationInputId: input,
            configurationDigest: digest,
          },
        };
        await fault(() =>
          client.query(`insert into ${probeSchema}.deletion_job values($1,$2,$3,$4,$5)`, [
            ...scope,
            job,
            'RUNTIME_ARTIFACT',
            selection,
          ]),
        );
      }
      await fault(() =>
        client.query(
          `insert into ${probeSchema}.idempotency_record(participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key) values($1,$2,$3,$4,$5,$6)`,
          [
            ...scope,
            candidate.maker_principal_id,
            candidate.action_intent_id,
            candidate.catalog_operation_id,
            candidate.idempotency_key,
          ],
        ),
      );
      await fault(() =>
        client.query(`insert into ${probeSchema}.receipt_signing_attempt values($1,$2,$3,$4)`, [
          ...scope,
          Buffer.from('d1f1c8ccfbd049063197e8511e1b0604888963b29cc40fec7ca8e72f539d85c5', 'hex'),
          id(),
        ]),
      );
      for (const aggregate of [candidate.resource_id, id()]) {
        await fault(() =>
          client.query(`insert into ${probeSchema}.audit_occurrence values($1,$2,$3,$4)`, [
            ...scope,
            aggregate,
            candidate.candidate_digest,
          ]),
        );
        await fault(() =>
          client.query(`insert into ${probeSchema}.mutation_evidence values($1,$2,$3,$4,$5)`, [
            ...scope,
            aggregate,
            candidate.catalog_operation_id,
            candidate.candidate_digest,
          ]),
        );
      }
      await fault(() =>
        client.query(`insert into ${probeSchema}.outbox_event values($1,$2,$3)`, [
          ...scope,
          candidate.resource_id,
        ]),
      );
      await faultProof();
      await client.query('rollback');
      process.stdout.write(
        `OPENPC_RUNTIME_RETIREMENT_RECOVERY|PASS|guard=${mode === 'prepared' ? 'prepared' : 'installed'}|exact-original-candidate|actual-runtime-role|no-effect|foreign-and-raw-denial|producer-exclusion|isolated-effect-faults\n`,
      );
    }
  } finally {
    await client.query('rollback');
    await other.query('rollback');
    client.release();
    other.release();
  }
  if (mode === 'resume') {
    const artifacts = await mkdtemp(join(output, 'approval-recovery-browser-'));
    await withTransactionBrowser(
      {
        secretRoot: join(root, 'secrets'),
        evidenceRoot: evidence,
        artifacts,
        privacyDomainId: sourceScope.privacy,
        reuseSessions: true,
      },
      async ({ maker, checker, actors }) => {
        let { approvalId, current } = await readRuntimeRetirementApprovalChain(
          (approval) => readWorkbenchApproval(maker, approval),
          originalApproval,
          { body, key: candidate.idempotency_key, resourceRef: proposal.resourceRef },
        );
        assert.equal(
          current.candidate.operationRef,
          null,
          'Reconcile the committed retirement suffix',
        );
        await requireNewObservation('admission');
        await requireNewObservation('replay');
        if (current.candidate.canRequestResume) {
          const observation = `successor-approval-${approvalId}`;
          await requireNewObservation(observation);
          const [response] = await Promise.all([
            maker.waitForResponse(
              (r) =>
                r.request().method() === 'POST' &&
                new URL(r.url()).pathname === '/api/v1/ui/transaction-workbench' &&
                r.request().postDataJSON()?.command === 'RESUME',
            ),
            maker.getByRole('button', { name: 'Request fresh approval', exact: true }).click(),
          ]);
          assert.equal(response.status(), 202);
          const resumed = await response.json();
          approvalId = resumed.approvalId;
          await save(observation, resumed);
          current = await readWorkbenchApproval(maker, approvalId);
        }
        assert.deepEqual(current.candidate.candidate, body);
        assert.equal(current.candidate.resourceRef, proposal.resourceRef);
        const executionObservation = `browser-execution-${approvalId}`;
        await requireNewObservation(executionObservation);
        // The first retained r4 files predate attempt-specific names. Do not
        // silently replay that observed denial under the same approval.
        const legacy = await json('successor-approval').catch((error) => {
          if (error.code === 'ENOENT') return null;
          throw error;
        });
        if (legacy?.approvalId === approvalId) await requireNewObservation('browser-execution');
        const review = await readWorkbenchApproval(checker, approvalId);
        assert.deepEqual(review.candidate.candidate, body);
        assert.equal(review.candidate.runtimePermission, 'NONE');
        if (!review.candidate.approvalUsable) {
          await checker
            .getByRole('button', { name: 'Approve with security key', exact: true })
            .click();
          await expect(
            checker.getByText('Independent approval recorded.', { exact: true }),
          ).toBeVisible();
        }
        const approved = await readWorkbenchApproval(maker, approvalId);
        assert.equal(approved.candidate.approvalUsable, true);
        assert.equal(approved.candidate.operationRef, null);
        const start = Date.now();
        const [executed] = await Promise.all([
          maker.waitForResponse(
            (r) =>
              r.request().method() === 'POST' &&
              new URL(r.url()).pathname === '/api/v1/ui/transaction-workbench' &&
              r.request().postDataJSON()?.command === 'EXECUTE',
          ),
          maker.getByRole('button', { name: 'Execute approved request', exact: true }).click(),
        ]);
        const result = await executed.json();
        await save(executionObservation, { status: executed.status(), result });
        assert.equal(executed.status(), 202, result.code);
        assert.equal(result.operation.state, 'SUCCEEDED');
        assert.equal(result.operation.idempotencyKey, candidate.idempotency_key);
        assert.equal(result.operation.resourceRef, proposal.resourceRef);
        await save('admission', result.operation);
        const observe = (phase) =>
          promisify(execFile)(
            process.execPath,
            [
              '--import',
              'tsx',
              'tests/integration/local-runtime/runtime-source-retirement-journey.mjs',
              'effect',
              root,
              composeText,
              phase,
            ],
            { timeout: 15000, maxBuffer: 1024 * 1024 },
          );
        await observe('before-replay');

        // Immediate exact public replay precedes native polling, restart or visuals.
        const origin = 'http://127.0.0.1:8080';
        const headers = {
          'Cookie': `__Host-openpc_session=${actors.maker.sessionToken}`,
          'Content-Type': 'application/json',
          'Origin': origin,
        };
        const csrf = await fetch(`${origin}/api/v1/session/csrf`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ actionIntentId: operation.actionIntentId }),
        });
        assert.equal(csrf.status, 200);
        const csrfToken = (await csrf.json()).csrfToken;
        assert.equal(typeof csrfToken, 'string');
        const replay = await fetch(`${origin}/api/v1/evidence-deletions/runtime-batches`, {
          method: 'POST',
          headers: {
            ...headers,
            'X-CSRF-Token': csrfToken,
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': body.participantId,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${sourceScope.privacy}`,
            'X-Request-ID': id(),
            'X-Correlation-ID': id(),
            'Idempotency-Key': candidate.idempotency_key,
            'OpenPC-Action-Intent-Digest': body.actionIntentDigest,
          },
          body: JSON.stringify(body),
        });
        const repeated = await replay.json();
        await save('replay', repeated);
        assert.equal(replay.status, 202, repeated.code);
        assert.deepEqual(repeated, result.operation);
        await observe('after-replay');
        const completed = await readWorkbenchApproval(maker, approvalId);
        assert.equal(completed.candidate.state, 'CONSUMED');
        assert.equal(completed.candidate.resourceRef, proposal.resourceRef);
        assert.deepEqual(
          completed.operation,
          Object.fromEntries(
            ['operationId', 'state', 'truthState', 'revision', 'updatedAt'].map((key) => [
              key,
              result.operation[key],
            ]),
          ),
        );
        assert.equal(completed.resultUnavailable, false);
        assert.equal(completed.operationUnavailable, false);
        assert.equal(completed.result.deletionJobId, proposal.resourceRef);
        await maker.screenshot({
          path: join(artifacts, 'retirement-committed.png'),
          fullPage: true,
        });
        process.stdout.write(
          `OPENPC_RUNTIME_RETIREMENT_RECOVERY|PASS|public-successor-checker-execution|same-intent-exact-live-replay|authority-phase-ms=${Date.now() - start}\n`,
        );
      },
    );
  }
} finally {
  await runtime.end();
  if (probeCreated) await admin.query(`drop schema ${probeSchema} cascade`);
  await admin.end();
}
