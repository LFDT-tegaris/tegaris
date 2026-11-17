import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  governThroughWorkbench,
  readWorkbenchApproval,
  withTransactionBrowser,
} from './transaction-workbench-browser.mjs';
import {
  verifyReceiptCose,
  decodeAdmittedReceipt,
} from '../../../packages/security-kernel/src/index.ts';

const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [secretRoot, participantId, privacyDomainId, composeJson] = process.argv.slice(2);
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const artifacts = join(secretRoot, '..', 'evidence', 'retention-policy-browser');
await mkdir(artifacts, { recursive: true, mode: 0o700 });
if (!(await readFile(join(artifacts, 'deployment-intent-actors.json'), 'utf8').catch(() => null)))
  await exec(
    process.execPath,
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/deployment-intent-actors.mjs',
      secretRoot,
      artifacts,
      participantId,
      'bootstrap-retention',
    ],
    { timeout: 30000, maxBuffer: 65536 },
  );
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  max: 1,
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
try {
  await withTransactionBrowser(
    { secretRoot, evidenceRoot: artifacts, artifacts, route: '/operate/evidence' },
    async ({ maker, checker, actors }) => {
      const verify = async (view, verb) => {
        const operation =
          verb === 'activate' ? view.activationOperationId : view.retirementOperationId;
        const receipts = await pool.query(
          `select a.receipt_cbor,a.cose_sign1,a.receipt_digest,k.public_key_spki_der
        from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
        where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.aggregate_type='retention-policy'`,
          [participantId, privacyDomainId, operation],
        );
        assert.equal(receipts.rowCount, 1);
        const receipt = receipts.rows[0],
          decoded = decodeAdmittedReceipt(receipt.receipt_cbor);
        assert.equal(
          verifyReceiptCose(receipt.public_key_spki_der, receipt.receipt_cbor, receipt.cose_sign1),
          true,
        );
        assert.equal(decoded.transitionProfileId, `pc.control.retention-policy.${verb}`);
        assert.equal(decoded.operationId, operation);
        assert.notEqual(decoded.receiptId, operation);
        assert.equal(
          verb === 'activate' ? view.activationReceiptDigest : view.retirementReceiptDigest,
          `sha256:${receipt.receipt_digest.toString('hex')}`,
        );
      };
      const refresh = async () => {
        const pending = maker.waitForResponse(
          (r) => new URL(r.url()).pathname === '/api/v1/ui/evidence-workbench',
        );
        await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).focus();
        await maker.keyboard.press('Enter');
        const response = await pending;
        assert.equal(response.status(), 200);
        const view = await response.json();
        assert.equal(view.retentionPoliciesUnavailable, false);
        assert.equal(
          view.retentionPolicies.nextCursor,
          null,
          'this isolated retained policy fixture must fit one complete page',
        );
        return view.retentionPolicies.items;
      };
      const retire = async (ref, reason) => {
        const result = await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: 'Retire a retention policy version',
          fields: { 'Resource reference': ref, 'Expected revision': '1' },
          reason,
        });
        assert.equal(result.completed.result.state, 'RETIRED');
        assert.ok(result.completed.result.activeUntil);
        await verify(result.completed.result, 'retire');
        return result;
      };
      let prior = await refresh();
      // A classified retry finishes only this actor's earlier public activation.
      // It never edits policy state or an approval directly in the database.
      for (const policy of prior.filter(
        (p) => p.state === 'ACTIVE' && ['AUDIT_EVIDENCE', 'RAW_SOURCE_BODY'].includes(p.dataClass),
      )) {
        const owner = await pool.query(
          `select principal_id::text from control.mutation_evidence where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
          [participantId, privacyDomainId, policy.activationOperationId],
        );
        assert.equal(owner.rowCount, 1);
        assert.equal(owner.rows[0].principal_id, actors.maker.principalId);
        await retire(
          policy.retentionPolicyId,
          `Finish the prior isolated retention investigation ${policy.retentionPolicyId}.`,
        );
      }
      prior = await refresh();
      const predecessor = (dataClass) =>
        prior
          .filter((p) => p.dataClass === dataClass)
          .sort((a, b) => b.activeFrom.localeCompare(a.activeFrom))[0]?.retentionPolicyId;
      const version = `0.${Date.now()}`;
      const activate = async (dataClass, suffix, previous, expectedExecutionStatus = 202) => {
        const result = await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: 'Activate a retention policy version',
          fields: {
            'Retained data class': dataClass,
            'Retention policy version': `${version}.${suffix}`,
            ...(previous ? { 'Previous retention policy reference (optional)': previous } : {}),
            'Retention period in milliseconds':
              dataClass === 'AUDIT_EVIDENCE' ? '3600000' : '86400000',
            'Local grace in milliseconds': '60000',
            'Required durable sink acknowledgements': '2',
            'Deletion mode': 'ROW_DELETE',
            'Require independent deletion approval': 'true',
          },
          reason: `Set exact ${dataClass} retention requirements for investigation ${version}.${suffix}.`,
          expectedExecutionStatus,
        });
        if (expectedExecutionStatus === 202) {
          assert.equal(result.completed.result.state, 'ACTIVE');
          assert.equal(result.completed.result.activeUntil, null);
          await verify(result.completed.result, 'activate');
        } else assert.equal(result.problem.code, 'PC-DATA-6007');
        return result;
      };
      const first = await activate('AUDIT_EVIDENCE', 0, predecessor('AUDIT_EVIDENCE'));
      const firstRef = first.completed.result.retentionPolicyId;
      await activate('AUDIT_EVIDENCE', 1, firstRef, 412);
      const independent = await activate('RAW_SOURCE_BODY', 0, predecessor('RAW_SOURCE_BODY'));
      const firstRetirement = await retire(
        firstRef,
        `Retire the original audit policy ${version} before its successor.`,
      );
      const successor = await activate('AUDIT_EVIDENCE', 2, firstRef);
      const successorRef = successor.completed.result.retentionPolicyId;
      await exec(compose[0], [...compose.slice(1), 'restart', 'control-api'], {
        timeout: 30000,
        maxBuffer: 65536,
      });
      await exec(
        compose[0],
        [
          ...compose.slice(1),
          'up',
          '-d',
          '--wait',
          '--no-deps',
          '--no-build',
          '--pull',
          'never',
          'control-api',
        ],
        { timeout: 30000, maxBuffer: 65536 },
      );
      const old = await readWorkbenchApproval(maker, first.approvalId);
      assert.equal(old.result.state, 'RETIRED');
      assert.equal(
        old.result.activationReceiptDigest,
        first.completed.result.activationReceiptDigest,
      );
      assert.equal(
        old.result.retirementReceiptDigest,
        firstRetirement.completed.result.retirementReceiptDigest,
      );
      const restored = await readWorkbenchApproval(maker, successor.approvalId);
      assert.equal(restored.result.state, 'ACTIVE');
      assert.equal(restored.result.predecessorPolicyId, firstRef);
      assert.equal(
        restored.result.activationReceiptDigest,
        successor.completed.result.activationReceiptDigest,
      );
      const policies = await refresh();
      assert.equal(
        policies.filter((p) => p.dataClass === 'AUDIT_EVIDENCE' && p.state === 'ACTIVE').length,
        1,
      );
      const raw = policies.find(
        (p) => p.retentionPolicyId === independent.completed.result.retentionPolicyId,
      );
      assert.equal(raw.retentionPeriodMs, '86400000');
      assert.equal(raw.state, 'ACTIVE');
      const region = maker.getByRole('region', { name: 'Retention policies', exact: true });
      await expect(region.locator('li').filter({ hasText: successorRef })).toContainText(
        '3600000 ms',
      );
      await expect(region.locator('li').filter({ hasText: firstRef }).first()).toBeVisible();
      await expect(region).toContainText(firstRetirement.completed.result.retirementReceiptDigest);
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({ path: join(artifacts, 'retention-desktop.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 800 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        true,
      );
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({ path: join(artifacts, 'retention-reflow.png'), fullPage: true });
    },
  );
  process.stdout.write(
    'OPENPC_RETENTION_POLICIES|PASS|real-governance|independent-classes|no-default-period|one-active-version|separate-retirement|signed-transitions|restart-readback|keyboard|axe|reflow|no-deletion-requested\n',
  );
} finally {
  await pool.end();
}
