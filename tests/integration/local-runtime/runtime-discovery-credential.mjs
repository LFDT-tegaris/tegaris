import { selectWorkloadPrincipals } from './workload-principal-selection.ts';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { expect } from '@playwright/test';
import { Pool } from 'pg';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { withTransactionBrowser } from './transaction-workbench-browser.mjs';

// External CA input and an initial workload principal are fixture prerequisites.
// Approval, WebAuthn, issuance, credential state and certificate readback are real.
const [secretRoot, evidenceRoot, inputFile] = process.argv.slice(2);
await promisify(execFile)(
  'bash',
  ['scripts/maintenance/run-bounded.sh', '--profile', 'runtime-target', '--reuse', '--', 'true'],
  { maxBuffer: 1024 * 1024 },
);
const input = JSON.parse(await readFile(inputFile, 'utf8'));
for (const field of ['participantId', 'privacyDomainId', 'principalId', 'credentialId', 'targetId'])
  assert.match(
    input[field],
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const workloadId = `urn:openpc:workload:${input.targetId}`;
const publicKey = createPublicKey(createPrivateKey(await readFile(input.privateKeyPath))).export({
  type: 'spki',
  format: 'der',
});
const artifacts = join(evidenceRoot, 'runtime-discovery-credential', uuidv7());
const endpoint = '/api/v1/ui/workload-workbench';
const pool = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
try {
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot,
      artifacts,
      route: '/develop/modules',
      privacyDomainId: input.privacyDomainId,
      reuseSessions: true,
    },
    async ({ maker, checker, actors }) => {
      for (const page of [maker, checker])
        await page.goto('http://localhost:8080/govern/memberships?view=workloads');
      const existing = await pool.query(
        'select credential_id from control.credential where participant_id=$1 and credential_id=$2',
        [input.participantId, input.credentialId],
      );
      if (existing.rowCount === 0) {
        await maker.getByRole('combobox', { name: /^Change/u }).selectOption('ISSUE');
        await maker
          .getByRole('textbox', { name: 'New credential ID', exact: true })
          .fill(input.credentialId);
        const checkerKind = await pool.query(
          'select kind from control.principal where participant_id=$1 and principal_id=$2',
          [input.participantId, actors.checker.principalId],
        );
        assert.equal(checkerKind.rowCount, 1);
        assert.ok(['USER', 'PLATFORM_OPERATOR'].includes(checkerKind.rows[0].kind));
        await selectWorkloadPrincipals(maker, {
          workloadPrincipalId: input.principalId,
          checkerPrincipalId: actors.checker.principalId,
          checkerKind: checkerKind.rows[0].kind,
        });
        await maker.getByRole('textbox', { name: 'Workload ID', exact: true }).fill(workloadId);
        await maker
          .getByRole('textbox', { name: 'Workload public key', exact: true })
          .fill(publicKey.toString('base64'));
        await maker
          .getByRole('textbox', { name: 'Reason for workload change', exact: true })
          .fill(
            'Issue the exact registered target workload for authenticated non-serving discovery.',
          );
        const responseFor = (page, command) =>
          page.waitForResponse(
            (response) =>
              response.url().endsWith(endpoint) &&
              response.request().method() === 'POST' &&
              response.request().postDataJSON()?.command === command,
          );
        const preparedResponse = responseFor(maker, 'PREPARE');
        await maker.getByRole('button', { name: 'Prepare workload change', exact: true }).click();
        const prepared = await (await preparedResponse).json();
        assert.equal(prepared.review?.mutation, 'ISSUE');
        await writeFile(join(artifacts, 'prepared.json'), JSON.stringify(prepared), {
          mode: 0o600,
        });
        const submittedResponse = responseFor(maker, 'SUBMIT');
        await maker.getByRole('button', { name: 'Request workload approval', exact: true }).click();
        const submitted = await (await submittedResponse).json();
        await writeFile(join(artifacts, 'submitted.json'), JSON.stringify(submitted), {
          mode: 0o600,
        });
        const approvalId = submitted.approval?.approvalRequestId?.slice(-36);
        assert.match(approvalId, /^[0-9a-f-]{36}$/u);
        await checker
          .getByRole('button', { name: 'Refresh workload approvals', exact: true })
          .click();
        const article = checker.getByRole('article').filter({ hasText: approvalId });
        await expect(article).toContainText(prepared.review.candidateDigest);
        const approvedResponse = responseFor(checker, 'APPROVE');
        await article
          .getByRole('button', { name: 'Verify and approve workload change', exact: true })
          .click();
        assert.equal((await approvedResponse).ok(), true);
        const committedResponse = responseFor(maker, 'COMMIT');
        await maker
          .getByRole('button', { name: 'Verify and commit workload change', exact: true })
          .click();
        assert.equal((await committedResponse).ok(), true);
        await expect(
          maker.getByLabel('Workload certificate result', { exact: true }),
        ).toContainText('State: ACTIVE');
      }
      const readback = await maker.evaluate(
        async ({ endpoint, credentialId }) => {
          const response = await fetch(`${endpoint}?credentialId=${credentialId}`);
          return { status: response.status, body: await response.json() };
        },
        { endpoint, credentialId: input.credentialId },
      );
      assert.equal(readback.status, 200);
      await writeFile(join(artifacts, 'readback.json'), JSON.stringify(readback.body), {
        mode: 0o600,
      });
      const rows = (
        await pool.query(
          `select principal_id::text,kind,state,subject,audience,certificate_der,public_key_spki_der
         from control.credential where participant_id=$1 and credential_id=$2`,
          [input.participantId, input.credentialId],
        )
      ).rows;
      assert.equal(rows.length, 1);
      const row = rows[0];
      assert.equal(row.principal_id, input.principalId);
      assert.equal(row.kind, 'WORKLOAD_MTLS');
      assert.equal(row.state, 'ACTIVE');
      assert.equal(row.audience, workloadId);
      assert.equal(
        row.subject,
        `urn:openpc:participant:${input.participantId}:workload:${input.targetId}`,
      );
      assert.deepEqual(row.public_key_spki_der, publicKey);
      assert.equal(readback.body.credentialId, input.credentialId);
      assert.equal(readback.body.state, 'ACTIVE');
      assert.equal(readback.body.workloadId, workloadId);
      const publicDer = Buffer.from(readback.body.certificateDer, 'base64');
      assert.deepEqual(publicDer, row.certificate_der);
      const certificate = new X509Certificate(publicDer);
      assert.equal(certificate.subjectAltName, `URI:${row.subject}`);
      assert.deepEqual(
        Buffer.from(certificate.publicKey.export({ type: 'spki', format: 'der' })),
        publicKey,
      );
      await writeFile(input.certificateOutput, certificate.toString(), { mode: 0o444 });
      for (const actor of Object.values(actors))
        actor.nextSignCount = String(
          Number(
            (
              await pool.query(
                'select authenticator_sign_count n from control.credential where credential_id=$1',
                [actor.credentialId],
              )
            ).rows[0].n,
          ) + 1,
        );
      await writeFile(join(evidenceRoot, 'deployment-intent-actors.json'), JSON.stringify(actors), {
        mode: 0o600,
      });
      process.stdout.write(
        'OPENPC_RUNTIME_DISCOVERY_CREDENTIAL|PASS|public-issuer|independent-approval|WebAuthn|exact-target-key|durable-current-credential\n',
      );
    },
  );
} finally {
  await pool.end();
}
