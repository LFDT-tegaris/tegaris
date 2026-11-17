import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import { withTransactionBrowser, readWorkbenchApproval } from './transaction-workbench-browser.mjs';
import { sourceScope } from './runtime-source-bootstrap.mjs';

// Recover the original failed retention request. The database is observation
// only; approval renewal and execution use the existing public Workbench.
const [mode, root] = process.argv.slice(2);
assert.ok(['preflight', 'resume', 'committed'].includes(mode));
const evidence = join(root, 'evidence/runtime-bootstrap');
const output = join(evidence, 'runtime-source-disposition');
const original = JSON.parse(await readFile(join(output, 'retention-approval.json')));
const approvalId = original.resourceRef.slice(-36);
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
try {
  const intent = (
    await pool.query(
      `select c.* from control.mutation_candidate c join control.approval_request a on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id and a.subject_id=c.mutation_candidate_id where a.participant_id=$1 and a.privacy_domain_id=$2 and a.approval_request_id=$3`,
      [sourceScope.participant, sourceScope.privacy, approvalId],
    )
  ).rows;
  assert.equal(intent.length, 1);
  const candidate = intent[0];
  assert.equal(candidate.catalog_operation_id, 'CFG-OP-ACTIVATE-RETENTION-POLICY');
  assert.equal(candidate.idempotency_key, 'runtime-source-retention-0001');
  assert.equal(candidate.consumed_operation_id, null);
  const counts = async () =>
    (
      await pool.query(
        `select
    (select count(*)::int from control.retention_policy where participant_id=$1 and privacy_domain_id=$2) policies,
    (select count(*)::int from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2 and catalog_operation_id=$3 and idempotency_key=$4) operations,
    (select count(*)::int from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='retention-policy') receipts,
    (select count(*)::int from control.receipt_signing_attempt a join control.business_transition_profile p using(profile_digest) where a.participant_id=$1 and a.privacy_domain_id=$2 and p.aggregate_type='retention-policy') attempts`,
        [
          sourceScope.participant,
          sourceScope.privacy,
          candidate.catalog_operation_id,
          candidate.idempotency_key,
        ],
      )
    ).rows[0];
  if (mode === 'committed') {
    assert.deepEqual(await counts(), { policies: 1, operations: 1, receipts: 1, attempts: 1 });
    const operation = JSON.parse(await readFile(join(output, 'retention-recovered.json')));
    assert.equal(operation.resourceRef, `urn:openpc:resource:${candidate.resource_id}`);
    assert.equal(operation.idempotencyKey, candidate.idempotency_key);
    assert.equal(operation.state, 'SUCCEEDED');
    const observed = await pool.query(
      `select p.retention_policy_id from control.retention_policy p
      join control.audit_occurrence a on a.participant_id=p.participant_id and a.privacy_domain_id=p.privacy_domain_id and a.operation_id=p.activation_operation_id and a.aggregate_id=p.retention_policy_id and a.aggregate_type='retention-policy'
      join control.idempotency_record i on i.participant_id=p.participant_id and i.privacy_domain_id=p.privacy_domain_id and i.operation_id=p.activation_operation_id
      join control.receipt_signing_attempt s on s.participant_id=p.participant_id and s.privacy_domain_id=p.privacy_domain_id and s.operation_id=p.activation_operation_id
      where p.participant_id=$1 and p.privacy_domain_id=$2 and p.retention_policy_id=$3 and p.activation_operation_id=$4 and i.idempotency_key=$5`,
      [
        sourceScope.participant,
        sourceScope.privacy,
        candidate.resource_id,
        operation.operationId,
        candidate.idempotency_key,
      ],
    );
    assert.equal(observed.rowCount, 1);
    process.stdout.write(
      'OPENPC_RUNTIME_SOURCE_RECOVERY|PASS|original-retention-committed|same-policy-operation-receipt-signing-attempt\n',
    );
  } else {
    assert.deepEqual(await counts(), { policies: 0, operations: 0, receipts: 0, attempts: 0 });
  }
  if (mode === 'preflight') {
    process.stdout.write(
      'OPENPC_RUNTIME_SOURCE_RECOVERY|PASS|original-retention-unconsumed|no-policy-operation-receipt-signing-attempt\n',
    );
  } else if (mode === 'resume') {
    await withTransactionBrowser(
      {
        secretRoot: join(root, 'secrets'),
        evidenceRoot: evidence,
        artifacts: join(output, 'retention-resume-browser'),
        privacyDomainId: sourceScope.privacy,
        reuseSessions: true,
      },
      async ({ maker, checker }) => {
        const old = await readWorkbenchApproval(maker, approvalId);
        assert.equal(old.candidate.canRequestResume, true);
        assert.equal(old.candidate.approvalUsable, false);
        assert.equal(old.candidate.resourceRef, `urn:openpc:resource:${candidate.resource_id}`);
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
        const next = await readWorkbenchApproval(checker, resumed.approvalId);
        assert.deepEqual(next.candidate.candidate, candidate.candidate_document);
        assert.equal(next.candidate.resourceRef, old.candidate.resourceRef);
        assert.equal(next.candidate.attempt, String(BigInt(old.candidate.attempt) + 1n));
        await checker
          .getByRole('button', { name: 'Approve with security key', exact: true })
          .click();
        await expect(
          checker.getByText('Independent approval recorded.', { exact: true }),
        ).toBeVisible();
        const approved = await readWorkbenchApproval(maker, resumed.approvalId);
        assert.equal(approved.candidate.approvalUsable, true);
        const [executed] = await Promise.all([
          maker.waitForResponse(
            (r) =>
              r.request().method() === 'POST' &&
              new URL(r.url()).pathname === '/api/v1/ui/transaction-workbench' &&
              r.request().postDataJSON()?.command === 'EXECUTE',
          ),
          maker.getByRole('button', { name: 'Execute approved request', exact: true }).click(),
        ]);
        assert.equal(executed.status(), 202);
        const { operation } = await executed.json();
        assert.equal(operation.state, 'SUCCEEDED');
        assert.equal(operation.idempotencyKey, candidate.idempotency_key);
        assert.equal(operation.resourceRef, old.candidate.resourceRef);
        assert.deepEqual(await counts(), { policies: 1, operations: 1, receipts: 1, attempts: 1 });
        await writeFile(join(output, 'retention-recovered.json'), JSON.stringify(operation), {
          flag: 'wx',
          mode: 0o600,
        });
        process.stdout.write(
          'OPENPC_RUNTIME_SOURCE_RECOVERY|PASS|same-intent|public-resume|independent-WebAuthn|one-retention-effect\n',
        );
      },
    );
  }
} finally {
  await pool.end();
}
