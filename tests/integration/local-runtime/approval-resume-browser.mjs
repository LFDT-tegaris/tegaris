import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, writeFile, copyFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { decodeBffSession } from '../../../apps/admin-web/app/api/v1/ui/local-runtime.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { readWorkbenchApproval, withTransactionBrowser } from './transaction-workbench-browser.mjs';

// Recover an original module request after its approval expires.
// The caller supplies a real previously approved, expired, unconsumed intent.
// No candidate, decision, business effect or expiry is seeded or rewritten here.
export async function approvalResumeBrowser({
  secretRoot,
  evidenceRoot,
  participantId,
  privacyDomainId,
  approvalId,
  project,
  readbackOnly = false,
  waitForExpiry = false,
}) {
  await promisify(execFile)(
    'bash',
    ['scripts/maintenance/run-bounded.sh', '--profile', 'runtime-target', '--reuse', '--', 'true'],
    { maxBuffer: 1024 * 1024 },
  );
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 2,
  });
  const artifacts = join(evidenceRoot, 'approval-resume-browser', uuidv7());
  const original = (
    await pool.query(
      `select to_jsonb(c) candidate,to_jsonb(r) approval,to_jsonb(d) decision,to_jsonb(m) proof
    from control.approval_request r join control.mutation_candidate c on c.mutation_candidate_id=r.subject_id
    join control.approval_decision_record d using(approval_request_id)
    join control.mfa_challenge m on m.mfa_challenge_id=d.mfa_challenge_id and m.participant_id=d.participant_id
    where r.participant_id=$1 and r.privacy_domain_id=$2 and r.approval_request_id=$3`,
      [participantId, privacyDomainId, approvalId],
    )
  ).rows;
  assert.equal(original.length, 1);
  const intent = original[0].candidate;
  assert.equal(intent.catalog_operation_id, 'MOD-OP-REGISTER');
  assert.equal(intent.consumed_operation_id, null);
  const moduleIndex = /^module-admission-(\d+)-0001$/u.exec(intent.idempotency_key)?.[1];
  assert.ok(moduleIndex, 'the caller supplies the existing module admission identity');
  const moduleOutput = join(evidenceRoot, `module-admission-${moduleIndex}.json`);
  if (waitForExpiry) {
    assert.equal(readbackOnly, false);
    const expiry = Math.min(
      Date.parse(original[0].proof.expires_at),
      Date.parse(original[0].proof.consumed_at) + 300000,
      Date.parse(original[0].approval.expires_at),
      Date.parse(intent.expires_at),
    );
    assert.ok(Number.isFinite(expiry));
    while (Date.now() <= expiry) {
      const remaining = expiry - Date.now() + 100;
      process.stdout.write(`OPENPC_APPROVAL_EXPIRY|natural|remaining_ms=${remaining}\n`);
      await delay(Math.min(30000, remaining));
    }
  }

  const scope = [participantId, privacyDomainId];
  const countEffects = async () =>
    (
      await pool.query(
        `select
    (select count(*)::int from control.module_installation where participant_id=$1 and privacy_domain_id=$2 and module_installation_id=$3) installations,
    (select count(*)::int from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2 and catalog_operation_id='MOD-OP-REGISTER' and idempotency_key=$4) operations,
    (select count(*)::int from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3) receipts`,
        [...scope, intent.resource_id, intent.idempotency_key],
      )
    ).rows[0];
  assert.deepEqual(
    await countEffects(),
    readbackOnly
      ? { installations: 1, operations: 1, receipts: 1 }
      : { installations: 0, operations: 0, receipts: 0 },
  );
  const cookieKey = Buffer.from(
    (await readFile(join(secretRoot, 'bff_cookie_key.txt'), 'utf8')).trim(),
  );
  process.stdout.write(`OPENPC_APPROVAL_RESUME_ARTIFACTS|${artifacts}\n`);
  try {
    await withTransactionBrowser(
      {
        secretRoot,
        evidenceRoot,
        artifacts,
        route: '/develop/modules',
        privacyDomainId,
        reuseSessions: true,
      },
      async ({ maker, checker, actors }) => {
        const sessions = {};
        for (const [name, page] of [
          ['maker', maker],
          ['checker', checker],
        ]) {
          const cookie = (await page.context().cookies()).find(
            (c) => c.name === 'openpc_local_runtime_session',
          );
          sessions[name] = decodeBffSession(cookie?.value, cookieKey);
          assert.ok(sessions[name]?.sessionToken);
          const identity = await page.evaluate(async () =>
            (await fetch('/api/v1/ui/local-session')).json(),
          );
          assert.equal(identity.principalId, actors[name].principalId);
          assert.equal(identity.participantId, participantId);
          assert.equal(identity.privacyDomainId, privacyDomainId);
          actors[name].sessionToken = sessions[name].sessionToken;
        }
        await writeFile(
          join(evidenceRoot, 'deployment-intent-actors.json'),
          JSON.stringify(actors),
          { mode: 0o600 },
        );
        const api = async (name, path, method = 'GET', body, key, context = {}) => {
          const headers = {
            'Cookie': `__Host-openpc_session=${sessions[name].sessionToken}`,
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': `urn:openpc:participant:${context.participantId ?? participantId}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${context.privacyDomainId ?? privacyDomainId}`,
            'X-Request-ID': uuidv7(),
            'X-Correlation-ID': uuidv7(),
          };
          if (body) {
            const csrf = await fetch('http://localhost:8080/api/v1/session/csrf', {
              method: 'POST',
              headers: {
                ...headers,
                'origin': 'http://localhost:8080',
                'content-type': 'application/json',
              },
              body: JSON.stringify({ actionIntentId: body.actionIntentId }),
            });
            assert.equal(csrf.status, 200, 'real CSRF owner');
            Object.assign(headers, {
              'X-CSRF-Token': (await csrf.json()).csrfToken,
              'origin': 'http://localhost:8080',
              'content-type': 'application/json',
              'Idempotency-Key': key,
              'X-OpenPC-Action-Intent-Digest': body.actionIntentDigest,
            });
            if (body.expectedRevision !== undefined)
              headers['If-Match'] =
                `"${sha256({ resourceId: path.split(':').at(-1), revision: body.expectedRevision })}"`;
          }
          const response = await fetch(`http://localhost:8080/api/v1/${path}`, {
            method,
            headers,
            ...(body ? { body: JSON.stringify(body) } : {}),
          });
          return { status: response.status, body: await response.json() };
        };
        const action = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
        const actionDigest = (
          await pool.query(
            "select 'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent where action_intent_id=$1",
            [action],
          )
        ).rows[0].digest;
        assert.equal(
          actionDigest,
          'sha256:dd2b80258905498007f0de87338d5044e8d7bb9b5d12d8336f28a67cdd9c2be9',
        );
        const resumeBody = (view) => ({
          command: 'RESUME',
          actionIntentId: action,
          actionIntentDigest: actionDigest,
          expectedRevision: view.approval.revision,
          predecessorCandidateId: view.candidate.attemptId,
          expectedAttempt: view.candidate.attempt,
          candidateDigest: view.candidate.candidateDigest,
          reason: 'Resume the unchanged request after approval expiry.',
        });
        const assertStaleResume = async (view) => {
          for (const change of [
            { expectedAttempt: String(BigInt(view.candidate.attempt) + 1n) },
            { expectedRevision: String(BigInt(view.approval.revision) + 1n) },
          ]) {
            const denied = await api(
              'maker',
              `approval-requests/urn:openpc:resource:${approvalId}`,
              'PATCH',
              { ...resumeBody(view), ...change },
              `stale-resume-${uuidv7()}`,
            );
            assert.equal(denied.status, 412);
            assert.equal(denied.body.code, 'PC-POLICY-2003');
            assert.equal(
              JSON.stringify(denied.body).includes(intent.candidate_document.name),
              false,
            );
          }
        };
        let nextId, execution;
        if (!readbackOnly) {
          await writeFile(
            join(artifacts, 'original-intent-history.json'),
            JSON.stringify(original),
          );
          const old = await readWorkbenchApproval(maker, approvalId);
          assert.equal(old.candidate.canRequestResume, true);
          assert.equal(old.candidate.approvalUsable, false);
          await expect(
            maker.getByRole('button', { name: 'Execute approved request', exact: true }),
          ).toBeDisabled();
          const checkerOld = await readWorkbenchApproval(checker, approvalId);
          assert.equal(checkerOld.reviewToken, undefined);
          assert.equal(checkerOld.candidate.businessIdempotencyKey, null);
          await expect(
            checker.getByRole('button', { name: 'Request fresh approval', exact: true }),
          ).toHaveCount(0);
          const path = `approval-requests/urn:openpc:resource:${approvalId}`;
          const resume = resumeBody(old),
            key = `workbench-resume-${old.candidate.attemptId}`;
          await assertStaleResume(old);
          for (const [name, body, context, statuses] of [
            ['maker', { ...resume, candidateDigest: `sha256:${'0'.repeat(64)}` }, {}],
            ['checker', resume, {}],
            ['maker', resume, { privacyDomainId: '018f0000-0000-7000-8000-000000006201' }],
            ['maker', resume, { participantId: '018f0000-0000-7000-8000-000000000102' }],
          ]) {
            const denied = await api(
              name,
              path,
              'PATCH',
              body,
              `resume-denial-${uuidv7()}`,
              context,
            );
            assert.ok(
              (statuses ?? [403, 404, 422]).includes(denied.status),
              `resume denial status ${denied.status}`,
            );
            assert.equal(
              JSON.stringify(denied.body).includes(intent.candidate_document.name),
              false,
            );
          }
          assert.deepEqual(await countEffects(), { installations: 0, operations: 0, receipts: 0 });
          let lost = false;
          const intercept = async (route) => {
            if (
              route.request().method() === 'POST' &&
              route.request().postDataJSON()?.command === 'RESUME' &&
              !lost
            ) {
              lost = true;
              const response = await route.fetch();
              assert.equal(response.status(), 202, `resume ${await response.text()}`);
              nextId = (await response.json()).approvalId;
              await route.abort('failed');
            } else await route.continue();
          };
          await maker.route('**/api/v1/ui/transaction-workbench', intercept);
          await maker.getByRole('button', { name: 'Request fresh approval', exact: true }).click();
          await expect.poll(() => lost && Boolean(nextId)).toBe(true);
          await maker.unroute('**/api/v1/ui/transaction-workbench', intercept);
          await readWorkbenchApproval(maker, approvalId);
          await expect(
            maker.getByRole('button', { name: 'Read resumed request', exact: true }),
          ).toBeVisible();
          await maker.getByRole('button', { name: 'Read resumed request', exact: true }).click();
          await expect(maker.getByLabel('Approval ID', { exact: true })).toHaveValue(nextId);
          const replay = await api('maker', path, 'PATCH', resume, key);
          assert.equal(replay.status, 202);
          assert.equal(replay.body.resourceRef, `urn:openpc:resource:${nextId}`);
          const altered = await api(
            'maker',
            path,
            'PATCH',
            { ...resume, reason: 'Altered replay' },
            key,
          );
          assert.equal(altered.status, 409);
          const conflict = await api(
            'maker',
            path,
            'PATCH',
            resume,
            `conflicting-resume-${uuidv7()}`,
          );
          assert.ok([403, 409].includes(conflict.status));
          assert.deepEqual(await countEffects(), { installations: 0, operations: 0, receipts: 0 });
          const next = await readWorkbenchApproval(checker, nextId);
          assert.equal(next.approval.state, 'REQUESTED');
          assert.equal(next.candidate.attempt, '2');
          assert.deepEqual(next.candidate.candidate, intent.candidate_document);
          assert.equal(next.candidate.resourceRef, `urn:openpc:resource:${intent.resource_id}`);
          await checker
            .getByRole('button', { name: 'Approve with security key', exact: true })
            .click();
          await expect(
            checker.getByText('Independent approval recorded.', { exact: true }),
          ).toBeVisible();
          const approved = await readWorkbenchApproval(maker, nextId);
          assert.equal(approved.candidate.approvalUsable, true);
          const loseExecution = async (route) => {
            if (
              route.request().method() === 'POST' &&
              route.request().postDataJSON()?.command === 'EXECUTE' &&
              !execution
            ) {
              const response = await route.fetch();
              assert.equal(response.status(), 202, `execution ${await response.text()}`);
              execution = (await response.json()).operation;
              await route.abort('failed');
            } else await route.continue();
          };
          await maker.route('**/api/v1/ui/transaction-workbench', loseExecution);
          const concurrentResume = api(
            'maker',
            `approval-requests/urn:openpc:resource:${nextId}`,
            'PATCH',
            resumeBody(approved),
            `current-resume-${uuidv7()}`,
          );
          await maker
            .getByRole('button', { name: 'Execute approved request', exact: true })
            .click();
          assert.ok([403, 409].includes((await concurrentResume).status));
          await expect.poll(() => Boolean(execution), { timeout: 30000 }).toBe(true);
          await maker.unroute('**/api/v1/ui/transaction-workbench', loseExecution);
          await expect(
            maker.getByText(
              'The response was lost. Read the approval and original result before retrying.',
              { exact: true },
            ),
          ).toBeVisible();
          assert.equal(execution.state, 'SUCCEEDED');
          assert.equal(execution.idempotencyKey, intent.idempotency_key);
          assert.deepEqual(await countEffects(), { installations: 1, operations: 1, receipts: 1 });
          await promisify(execFile)(
            'docker',
            [
              'compose',
              '-p',
              project,
              '-f',
              join(process.cwd(), 'deploy/compose/local/compose.yaml'),
              'restart',
              'identity-service',
              'policy-service',
              'control-api',
            ],
            { timeout: 90000, maxBuffer: 65536 },
          );
          await promisify(execFile)(
            'docker',
            [
              'compose',
              '-p',
              project,
              '-f',
              join(process.cwd(), 'deploy/compose/local/compose.yaml'),
              'up',
              '-d',
              '--wait',
              '--no-build',
              '--pull',
              'never',
              '--no-deps',
              'identity-service',
              'policy-service',
              'control-api',
            ],
            { timeout: 90000, maxBuffer: 65536 },
          );
          await maker.goto('http://localhost:8080/develop/modules');
        } else {
          const committed = (
            await pool.query(
              `select a.approval_request_id::text id,r.result_payload operation
            from control.mutation_candidate c join control.approval_request a on a.subject_id=c.mutation_candidate_id
            join control.idempotency_record r on r.operation_id=c.consumed_operation_id
              and r.participant_id=c.participant_id and r.privacy_domain_id=c.privacy_domain_id
            where c.predecessor_candidate_id=$1 and c.state='CONSUMED' and r.terminal_state='COMMITTED'`,
              [intent.mutation_candidate_id],
            )
          ).rows;
          assert.equal(committed.length, 1, 'one authoritative completed successor');
          nextId = committed[0].id;
          execution = committed[0].operation;
          const historical = await readWorkbenchApproval(maker, approvalId);
          assert.equal(historical.candidate.successorApprovalRef, `urn:openpc:resource:${nextId}`);
          assert.equal(historical.candidate.approvalUsable, false);
          assert.equal(historical.candidate.canRequestResume, false);
          await assertStaleResume(historical);
        }
        const completed = await readWorkbenchApproval(maker, nextId);
        assert.equal(completed.candidate.state, 'CONSUMED');
        assert.equal(completed.candidate.attempt, '2');
        assert.deepEqual(completed.candidate.candidate, intent.candidate_document);
        await readWorkbenchApproval(checker, nextId);
        assert.equal(completed.result.state, 'REGISTERED');
        assert.equal(
          completed.candidate.operationRef,
          `urn:openpc:operation:${execution.operationId}`,
        );
        if (readbackOnly) {
          // Historical reconciliation remains a read after mutation authority
          // expires. It must not renew the old approval or WebAuthn proof.
          const operation = await api('maker', `operations/${execution.operationId}`);
          assert.equal(operation.status, 200);
          assert.deepEqual(operation.body, execution);
        } else {
          const exact = await api(
            'maker',
            'modules',
            'POST',
            intent.candidate_document,
            intent.idempotency_key,
          );
          assert.equal(exact.status, 202);
          assert.deepEqual(exact.body, execution);
        }
        const consumed = await api(
          'maker',
          `approval-requests/urn:openpc:resource:${nextId}`,
          'PATCH',
          resumeBody(completed),
          `consumed-resume-${uuidv7()}`,
        );
        assert.ok([403, 409].includes(consumed.status));
        assert.deepEqual(await countEffects(), { installations: 1, operations: 1, receipts: 1 });
        const history = (
          await pool.query(
            `select to_jsonb(c) candidate,to_jsonb(r) approval,to_jsonb(d) decision,to_jsonb(m) proof
        from control.approval_request r join control.mutation_candidate c on c.mutation_candidate_id=r.subject_id
        join control.approval_decision_record d using(approval_request_id)
    join control.mfa_challenge m on m.mfa_challenge_id=d.mfa_challenge_id and m.participant_id=d.participant_id
        where r.participant_id=$1 and r.privacy_domain_id=$2 and r.approval_request_id=$3`,
            [...scope, approvalId],
          )
        ).rows;
        assert.deepEqual(
          history,
          original,
          'resumption must retain the original rows and consumed proof bytes',
        );
        await copyFile(moduleOutput, join(artifacts, 'prior-module-result.json')).catch((error) => {
          if (error.code !== 'ENOENT') throw error;
        });
        await writeFile(moduleOutput, JSON.stringify(execution));
        for (const [name, page] of [
          ['maker', maker],
          ['checker', checker],
        ]) {
          await expect(
            page.getByRole('heading', { name: 'Prepare a governed request', exact: true }),
          ).toBeVisible();
          const axe = await new AxeBuilder({ page }).analyze();
          assert.deepEqual(
            axe.violations.map((v) => v.id),
            [],
          );
          await page.keyboard.press('Tab');
          assert.equal(await page.evaluate(() => document.activeElement === document.body), false);
          await page.screenshot({ path: join(artifacts, `${name}-desktop.png`), fullPage: true });
          await page.setViewportSize({ width: 360, height: 900 });
          assert.equal(
            await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
            true,
            '360px reflow',
          );
          await page.screenshot({ path: join(artifacts, `${name}-mobile.png`), fullPage: true });
          actors[name].nextSignCount = String(
            Number(
              (
                await pool.query(
                  'select authenticator_sign_count count from control.credential where credential_id=$1',
                  [actors[name].credentialId],
                )
              ).rows[0].count,
            ) + 1,
          );
        }
        await writeFile(
          join(evidenceRoot, 'deployment-intent-actors.json'),
          JSON.stringify(actors),
          { mode: 0o600 },
        );
        process.stdout.write(
          readbackOnly
            ? 'OPENPC_APPROVAL_RESUME_READBACK|PASS|retained-committed-successor|same-intent|history|stale-resume-412|consumed-resume-denied|operation-readback|restart-readback|one-effect|axe|keyboard|360px-reflow\n'
            : 'OPENPC_APPROVAL_RESUME|PASS|same-intent|expiry|current-sessions|independent-WebAuthn|no-premature-effect|immutable-history-and-proofs|denials|concurrent-resume-replay|concurrent-execution|lost-responses|restart|one-effect|axe|keyboard|360px-reflow\n',
        );
      },
    );
  } finally {
    await pool.end();
  }
}
if (process.argv[1]?.endsWith('/approval-resume-browser.mjs')) {
  const [secretRoot, evidenceRoot, participantId, privacyDomainId, approvalId, project, phase] =
    process.argv.slice(2);
  await approvalResumeBrowser({
    secretRoot,
    evidenceRoot,
    participantId,
    privacyDomainId,
    approvalId,
    project,
    readbackOnly: phase === '--readback',
    waitForExpiry: phase === '--wait-for-expiry',
  });
}
