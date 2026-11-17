import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { isDeepStrictEqual, promisify } from 'node:util';
import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  withTransactionBrowser,
  governThroughWorkbench,
  readWorkbenchApproval,
} from './transaction-workbench-browser.mjs';
import { publicEvidenceReader } from './evidence-rejection-deletion-checks.mjs';
import { inspectProvenanceWorkbench } from './evidence-provenance-browser.mjs';
import { verifyPublicProvenance } from './evidence-provenance-checks.mjs';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import {
  transactionForms,
  transactionFields,
} from '../../../apps/admin-web/lib/transaction-workflow.ts';
import { transactionCandidate } from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
const exec = promisify(execFile);

export function sourceHoldRequests(participantId, lineage, rpc, reason) {
  return [
    { selectorType: 'PROJECTION', projectionId: lineage.projectionId },
    {
      selectorType: 'FACT_TYPE_KEY',
      factType: lineage.factType,
      factProfileId: lineage.factProfileId,
      factKeyDigest: lineage.factKeyDigest,
    },
    {
      selectorType: 'BLOCK_RANGE',
      chainId: lineage.chainId,
      genesisDigest: lineage.genesisDigest,
      fromBlock: lineage.blockNumber,
      throughBlock: lineage.blockNumber,
    },
    {
      selectorType: 'GENERATION',
      generationKind: 'CANONICAL_FACT',
      factProfileId: lineage.factProfileId,
      canonicalGeneration: lineage.canonicalGeneration,
    },
    {
      selectorType: 'GENERATION',
      generationKind: 'RUNTIME_CONFIGURATION',
      generationId: 'urn:openpc:resource:' + rpc.activation.generationId,
    },
  ].map((values) => {
    const input = { holdKind: 'INCIDENT', ...values };
    const candidate = transactionCandidate(
      'evidence-hold',
      transactionFields('evidence-hold', input),
      reason,
      participantId,
    );
    const fields = Object.fromEntries(
      Object.entries(input).map(([name, value]) => {
        const field = transactionForms['evidence-hold'].fields.find((field) => field.name === name);
        assert.ok(field, 'existing Workbench field owner');
        return [field.label + (field.optional ? ' (optional)' : ''), value];
      }),
    );
    return {
      fields,
      candidate: candidate.body,
      runtime: values.generationKind === 'RUNTIME_CONFIGURATION',
    };
  });
}

export async function chooseContext(page, privacyDomainId) {
  await page.goto('http://localhost:8080/govern/memberships?view=credentials');
  await page
    .getByRole('combobox', { name: 'Organization workspace', exact: true })
    .selectOption(privacyDomainId);
  const entered = page.waitForEvent('load');
  await page
    .getByRole('button', {
      name: 'Verify and enter workspace',
      exact: true,
    })
    .click();
  await entered;
  await page.goto('http://localhost:8080/operate/evidence');
  await expect(page.getByRole('region', { name: 'Evidence catalogue', exact: true })).toBeVisible();
}

// SEM-059: root governance is distinct from scoped child readback. All rules
// use public maker/checker/step-up owners and actual archived source identities.
export async function exerciseSourceHolds({
  secretRoot,
  participantId,
  privacyDomainId,
  factCustody,
  rpcRoot,
  rpcProvenance,
  compose,
}) {
  const legacyPrivacy = '018f0000-0000-7000-8000-000000000201';
  const scopeReader = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  let rootPrivacy, nonRootPrivacy;
  try {
    const { rows } = await scopeReader.query(
      `select p.root_privacy_domain_id::text root,
        array(select d.privacy_domain_id::text from control.privacy_domain d
          where d.participant_id=p.participant_id and d.state='ACTIVE'
          and d.privacy_domain_id=any($2::uuid[])) contexts
       from control.participant p where p.participant_id=$1 and p.state='ACTIVE'`,
      [participantId, [legacyPrivacy, privacyDomainId]],
    );
    assert.equal(rows.length, 1);
    rootPrivacy = rows[0].root;
    assert.deepEqual(rows[0].contexts.sort(), [legacyPrivacy, privacyDomainId].sort());
    assert.ok(rows[0].contexts.includes(rootPrivacy), 'existing actors must cover the actual root');
    nonRootPrivacy = rows[0].contexts.find((context) => context !== rootPrivacy);
    assert.ok(nonRootPrivacy);
  } finally {
    await scopeReader.end();
  }
  const artifacts = join(factCustody.root, 'hold-browser');
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  try {
    await readFile(join(artifacts, 'deployment-intent-actors.json'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await exec(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        secretRoot,
        artifacts,
        participantId,
        'bootstrap-evidence-source-holds',
        privacyDomainId,
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  }
  const worker = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_local_control_worker',
    password: (
      await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
    ).trim(),
    max: 1,
  });
  const rpcConfig = JSON.parse(await readFile(join(rpcRoot, 'worker.json'), 'utf8'));
  const configs = [factCustody.config, rpcConfig];
  const reason = `Preserve verified source lineage in ${factCustody.config.scopes[0].streamId}.`;
  // The installed source may be the participant root. Its positive scenario
  // is distinct from the preserved request made in the legacy child context.
  const rootReason = rootPrivacy === legacyPrivacy ? reason : `${reason} Root governance.`;
  const cases = sourceHoldRequests(
    participantId,
    factCustody.views[0].fact.lineage,
    rpcProvenance[0].rpc,
    reason,
  );
  const rootCandidate = transactionCandidate(
    'evidence-participant-hold',
    transactionFields('evidence-participant-hold', { holdKind: 'LEGAL' }),
    rootReason,
    participantId,
  ).body;
  const denialReason = reason + ' Child-context denial.';
  const sourceReleaseReason =
    'Release the verified source rule through its original scoped authority.';
  const rootReleaseReason = 'Release the root-governed preservation duty after its source checks.';
  let denialCandidate = transactionCandidate(
    'evidence-participant-hold',
    transactionFields('evidence-participant-hold', { holdKind: 'INCIDENT' }),
    denialReason,
    participantId,
  ).body;
  const inventory = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  let retainedRoot, retainedSources, retainedDenial, retainedReleases;
  try {
    const retained = await inventory.query(
      `select a.approval_request_id::text as "approvalId",c.maker_principal_id::text as "makerId",c.candidate_document candidate,c.privacy_domain_id::text privacy,c.catalog_operation_id catalog
       from control.mutation_candidate c join control.approval_request a on a.subject_id=c.mutation_candidate_id
        and a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
       where c.participant_id=$1 and c.privacy_domain_id=any($2::uuid[]) and c.catalog_operation_id in('CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-CREATE-EVIDENCE-HOLD')
        and c.candidate_document->>'reason'=any($3::text[]) and c.predecessor_candidate_id is null`,
      [participantId, [rootPrivacy, nonRootPrivacy], [reason, rootReason, denialReason]],
    );
    const participantOperation = 'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD';
    const roots = retained.rows.filter(
      (row) => row.privacy === rootPrivacy && row.catalog === participantOperation,
    );
    assert.ok(roots.length <= 1, 'one original Participant hold intent');
    retainedRoot = roots[0];
    if (retainedRoot) assert.deepEqual(retainedRoot.candidate, rootCandidate);
    const denials = retained.rows.filter(
      (row) => row.privacy === nonRootPrivacy && row.catalog === participantOperation,
    );
    assert.ok(denials.length <= 1, 'one original child denial intent');
    retainedDenial = denials[0];
    if (retainedDenial) {
      if (rootPrivacy !== legacyPrivacy && retainedDenial.candidate.reason === reason) {
        const original = transactionCandidate(
          'evidence-participant-hold',
          transactionFields('evidence-participant-hold', { holdKind: 'LEGAL' }),
          reason,
          participantId,
        ).body;
        assert.deepEqual(retainedDenial.candidate, original);
        denialCandidate = original;
      } else assert.deepEqual(retainedDenial.candidate, denialCandidate);
    }
    retainedSources = retained.rows.filter(
      (row) =>
        row.privacy === privacyDomainId &&
        row.catalog === 'CFG-OP-CREATE-EVIDENCE-HOLD' &&
        row.candidate.reason === reason,
    );
    for (const saved of retainedSources)
      assert.ok(
        cases.some((request) => isDeepStrictEqual(request.candidate, saved.candidate)),
        'only exact original source intents',
      );
    for (const request of cases)
      assert.ok(
        retainedSources.filter((saved) => isDeepStrictEqual(request.candidate, saved.candidate))
          .length <= 1,
        'one intent per source selector',
      );
    retainedReleases = (
      await inventory.query(
        `select a.approval_request_id::text as "approvalId",c.maker_principal_id::text as "makerId",c.candidate_document candidate,c.privacy_domain_id::text privacy,c.catalog_operation_id catalog
         from control.mutation_candidate c join control.approval_request a on a.subject_id=c.mutation_candidate_id
          and a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
         where c.participant_id=$1 and c.privacy_domain_id=any($2::uuid[])
          and c.catalog_operation_id in('CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD','CFG-OP-RELEASE-EVIDENCE-HOLD')
          and c.candidate_document->>'reason'=any($3::text[]) and c.predecessor_candidate_id is null`,
        [participantId, [rootPrivacy, privacyDomainId], [sourceReleaseReason, rootReleaseReason]],
      )
    ).rows;
  } finally {
    await inventory.end();
  }
  const custody = new EvidenceCustody(worker);
  const synchronize = async () => {
    for (const config of configs) {
      const sink = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId);
      for (const scope of config.scopes)
        for (let page = 0; page < 64; page++) {
          if (
            (await custody.reconcileHolds(
              {
                participantId: scope.participantId,
                privacyDomainId: scope.privacyDomainId,
                streamId: scope.streamId,
              },
              sink,
            )) === 0
          )
            break;
          assert.ok(page < 63, 'bounded hold reconciliation');
        }
    }
  };
  const checkCoverage = async (hold, expectedKnown) => {
    const client = await worker.connect();
    try {
      await client.query('begin read only');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        [participantId, privacyDomainId, uuidv7()],
      );
      const rows = (
        await client.query(
          `select c.stream_id,c.segment_id,openpc.evidence_hold_match_state($1,$2,$3,c.stream_id,c.segment_id) matched,
        exists(select 1 from control.evidence_hold_coverage h where h.participant_id=c.participant_id and h.privacy_domain_id=c.privacy_domain_id
         and h.retention_hold_id=$4 and h.hold_revision=$5 and h.stream_id=c.stream_id and h.segment_id=c.segment_id) covered
        from control.evidence_catalogue c where c.participant_id=$2 and c.privacy_domain_id=$3 and c.source_format in('OPENPC_CANONICAL_FACT_V1','OPENPC_RPC_DECISION_TRANSITION_V1')
        group by c.participant_id,c.privacy_domain_id,c.stream_id,c.segment_id`,
          [hold.selector, participantId, privacyDomainId, hold.holdId.slice(-36), hold.revision],
        )
      ).rows;
      assert.ok(
        rows.some((row) => row.matched === 'MATCH'),
        'real positive source match',
      );
      if (expectedKnown)
        assert.ok(rows.some((row) => row.stream_id === expectedKnown && row.matched === 'MATCH'));
      for (const row of rows)
        if (row.matched !== 'NON_MATCH')
          assert.equal(row.covered, true, 'matching and unknown sources remain preserved');
    } finally {
      await client.query('rollback');
      client.release();
    }
  };
  let resumedReleasedHold = false;
  try {
    await withTransactionBrowser(
      {
        secretRoot,
        evidenceRoot: artifacts,
        artifacts,
        route: '/operate/evidence',
        privacyDomainId: rootPrivacy,
      },
      async ({ maker, checker, actors }) => {
        const readOriginal = async (saved, candidate, states = ['ACTIVE', 'RELEASED']) => {
          assert.equal(saved.makerId, actors.maker.principalId);
          let approvalId = saved.approvalId;
          let completed = await readWorkbenchApproval(maker, approvalId);
          const businessKey = completed.candidate.businessIdempotencyKey;
          assert.ok(businessKey);
          const seen = new Set([approvalId]);
          // A supported expiry recovery retains the intent and business key.
          // Read its existing successor; this continuation submits no approval.
          while (completed.candidate.successorApprovalRef) {
            assert.deepEqual(completed.candidate.candidate, candidate);
            assert.equal(completed.candidate.businessIdempotencyKey, businessKey);
            assert.equal(completed.candidate.operationRef, null);
            const predecessorId = approvalId;
            approvalId = completed.candidate.successorApprovalRef.slice(-36);
            assert.ok(!seen.has(approvalId) && seen.size < 8, 'bounded approval history');
            seen.add(approvalId);
            completed = await readWorkbenchApproval(maker, approvalId);
            assert.equal(
              completed.candidate.predecessorApprovalRef,
              `urn:openpc:resource:${predecessorId}`,
            );
          }
          const review = await readWorkbenchApproval(checker, approvalId);
          assert.deepEqual(completed.candidate.candidate, candidate);
          assert.deepEqual(review.candidate.candidate, candidate);
          assert.equal(completed.candidate.businessIdempotencyKey, businessKey);
          assert.equal(completed.candidate.state, 'CONSUMED');
          assert.ok(states.includes(completed.result.state));
          if (states.includes('ACTIVE') && completed.result.state === 'RELEASED')
            resumedReleasedHold = true;
          return { approvalId, review, completed };
        };
        const releaseHold = async (hold, participantWide) => {
          const kind = participantWide
            ? 'evidence-participant-hold-release'
            : 'evidence-hold-release';
          const releaseReason = participantWide ? rootReleaseReason : sourceReleaseReason;
          const candidate = transactionCandidate(
            kind,
            transactionFields(kind, { targetRef: hold.holdId, expectedRevision: '1' }),
            releaseReason,
            participantId,
          ).body;
          const saved = retainedReleases.filter(
            (row) =>
              row.privacy === (participantWide ? rootPrivacy : privacyDomainId) &&
              row.catalog ===
                (participantWide
                  ? 'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD'
                  : 'CFG-OP-RELEASE-EVIDENCE-HOLD') &&
              isDeepStrictEqual(row.candidate, candidate),
          );
          assert.ok(saved.length <= 1, 'one original release intent per hold');
          let released;
          if (saved.length) {
            assert.equal(hold.state, 'RELEASED');
            released = await readOriginal(saved[0], candidate, ['RELEASED']);
            process.stdout.write('OPENPC_SOURCE_HOLDS|original-release-readback|no-resubmission\n');
          } else {
            assert.equal(
              hold.state,
              'ACTIVE',
              'released holds require their original consumed request',
            );
            released = await governThroughWorkbench({
              maker,
              checker,
              checkerId: actors.checker.principalId,
              label: transactionForms[kind].label,
              fields: { 'Resource reference': hold.holdId, 'Expected revision': '1' },
              reason: releaseReason,
            });
          }
          assert.equal(released.completed.result.holdId, hold.holdId);
          assert.equal(released.completed.result.state, 'RELEASED');
          assert.equal(released.completed.result.revision, '2');
          return released;
        };
        let participant;
        if (retainedRoot) {
          participant = await readOriginal(retainedRoot, rootCandidate);
          process.stdout.write('OPENPC_SOURCE_HOLDS|original-root-readback|no-resubmission\n');
        } else
          participant = await governThroughWorkbench({
            maker,
            checker,
            checkerId: actors.checker.principalId,
            label: transactionForms['evidence-participant-hold'].label,
            fields: { 'Hold kind': 'LEGAL' },
            reason: rootReason,
          });
        const participantHold = participant.completed.result;
        assert.equal(participantHold.selector.type, 'PARTICIPANT');
        assert.equal(participantHold.governancePrivacyDomainId, rootPrivacy);
        await chooseContext(maker, privacyDomainId);
        await chooseContext(checker, privacyDomainId);
        let api = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
        const participantPath = 'evidence-holds/' + participantHold.holdId;
        let child = await api(participantPath);
        assert.equal(child.status, 200);
        assert.equal(child.body.governancePrivacyDomainId, rootPrivacy);
        assert.equal(child.body.coveragePrivacyDomainId, privacyDomainId);
        await synchronize();
        await checkCoverage(child.body);
        const foreign = await api(participantPath, {
          participantId: '018f0000-0000-7000-8000-000000000102',
        });
        assert.equal(foreign.status, 403);
        assert.equal(JSON.stringify(foreign.body).includes(participantHold.holdId), false);
        await verifyPublicProvenance(api, factCustody.views, secretRoot);
        await inspectProvenanceWorkbench(maker, factCustody.views[0], artifacts);
        const holds = [];
        for (const request of cases) {
          const saved = retainedSources.find((saved) =>
            isDeepStrictEqual(saved.candidate, request.candidate),
          );
          const created = saved
            ? await readOriginal(saved, request.candidate)
            : await governThroughWorkbench({
                maker,
                checker,
                checkerId: actors.checker.principalId,
                label: transactionForms['evidence-hold'].label,
                fields: request.fields,
                reason,
              });
          const hold = created.completed.result;
          assert.ok(['ACTIVE', 'RELEASED'].includes(hold.state));
          assert.deepEqual(hold.selector, request.candidate.selector);
          await synchronize();
          await checkCoverage(
            hold,
            request.runtime
              ? rpcProvenance[0].custody.streamId
              : factCustody.views[0].custody.streamId,
          );
          const read = await api('evidence-holds/' + hold.holdId);
          assert.equal(read.status, 200);
          assert.deepEqual(read.body.selector, hold.selector);
          if (
            ['FACT_TYPE_KEY', 'BLOCK_RANGE'].includes(hold.selector.type) ||
            hold.selector.generation?.kind === 'CANONICAL_FACT'
          )
            assert.equal(
              read.body.coverage,
              'UNAVAILABLE',
              'unresolved RPC references remain visible',
            );
          holds.push(created);
        }
        // An independently approved child request still cannot govern a Participant-wide rule.
        await chooseContext(maker, nonRootPrivacy);
        await chooseContext(checker, nonRootPrivacy);
        const nonRootRead = await publicEvidenceReader(
          maker,
          secretRoot,
          participantId,
          nonRootPrivacy,
        );
        const scopedHold = await nonRootRead(participantPath);
        assert.equal(scopedHold.status, 200);
        assert.equal(scopedHold.body.governancePrivacyDomainId, rootPrivacy);
        assert.equal(scopedHold.body.coveragePrivacyDomainId, nonRootPrivacy);
        let denied;
        if (retainedDenial) {
          assert.equal(retainedDenial.makerId, actors.maker.principalId);
          let approvalId = retainedDenial.approvalId;
          let original = await readWorkbenchApproval(maker, approvalId);
          const originalKey = original.candidate.businessIdempotencyKey;
          assert.deepEqual(original.candidate.candidate, denialCandidate);
          assert.ok(['APPROVED', 'EXPIRED'].includes(original.candidate.state));
          if (original.candidate.state === 'EXPIRED')
            assert.ok(
              original.candidate.successorApprovalRef || original.candidate.canRequestResume,
              'expired denial must retain an authorized recovery path',
            );
          assert.equal(original.candidate.operationRef, null);
          for (let attempt = 0; attempt < 8; attempt++) {
            assert.deepEqual(original.candidate.candidate, denialCandidate);
            assert.equal(original.candidate.businessIdempotencyKey, originalKey);
            assert.equal(original.candidate.operationRef, null);
            assert.equal(original.result, null);
            if (original.candidate.successorApprovalRef)
              approvalId = original.candidate.successorApprovalRef.slice(-36);
            else if (original.candidate.canRequestResume) {
              await maker
                .getByRole('button', { name: 'Request fresh approval', exact: true })
                .click();
              await expect(
                maker.getByText(
                  'A fresh approval request is ready. The previous attempt remains in its history.',
                  { exact: true },
                ),
              ).toBeVisible();
              approvalId = await maker.getByLabel('Approval ID', { exact: true }).inputValue();
              assert.notEqual(approvalId, retainedDenial.approvalId);
            } else break;
            original = await readWorkbenchApproval(maker, approvalId);
          }
          const review = await readWorkbenchApproval(checker, approvalId);
          assert.deepEqual(review.candidate.candidate, denialCandidate);
          assert.equal(review.candidate.businessIdempotencyKey, null);
          if (review.approval.state === 'REQUESTED') {
            await checker
              .getByRole('button', { name: 'Approve with security key', exact: true })
              .click();
            await expect(
              checker.getByText('Independent approval recorded.', { exact: true }),
            ).toBeVisible();
          }
          original = await readWorkbenchApproval(maker, approvalId);
          assert.equal(original.candidate.businessIdempotencyKey, originalKey);
          assert.equal(original.candidate.approvalUsable, true);
          assert.ok(original.stepUp);
          assert.equal(typeof original.reviewToken, 'string');
          await expect(
            maker.getByRole('button', { name: 'Execute approved request', exact: true }),
          ).toBeEnabled();
          const [response] = await Promise.all([
            maker.waitForResponse(
              (r) =>
                r.request().method() === 'POST' &&
                new URL(r.url()).pathname === '/api/v1/ui/transaction-workbench' &&
                r.request().postDataJSON()?.command === 'EXECUTE',
            ),
            maker.getByRole('button', { name: 'Execute approved request', exact: true }).click(),
          ]);
          assert.equal(response.status(), 404);
          const problem = await response.json();
          await expect(
            maker.getByText(
              'The request was not authorized. Refresh the authenticated context before continuing.',
              { exact: true },
            ),
          ).toBeVisible();
          const completed = await readWorkbenchApproval(maker, approvalId);
          assert.equal(completed.candidate.operationRef, null);
          assert.equal(completed.result, null);
          denied = { problem, completed };
        } else
          denied = await governThroughWorkbench({
            maker,
            checker,
            checkerId: actors.checker.principalId,
            label: transactionForms['evidence-participant-hold'].label,
            fields: { 'Hold kind': 'INCIDENT' },
            reason: denialReason,
            // The shared BFF error owner conceals denied resources; Control's
            // root-scope owner returns 403 and the browser receives safe 404.
            expectedExecutionStatus: 404,
          });
        assert.equal(denied.problem.code, 'PC-AUTH-0005');
        await chooseContext(maker, privacyDomainId);
        await chooseContext(checker, privacyDomainId);
        for (const created of holds) {
          const release = await releaseHold(created.completed.result, false);
          assert.equal(release.completed.result.state, 'RELEASED');
          await synchronize();
          await checkCoverage(release.completed.result);
        }
        await chooseContext(maker, rootPrivacy);
        await chooseContext(checker, rootPrivacy);
        const released = await releaseHold(participantHold, true);
        assert.equal(released.completed.result.state, 'RELEASED');
        await synchronize();
        await exec(compose[0], [...compose.slice(1), 'restart', 'control-api'], {
          timeout: 120000,
          maxBuffer: 65536,
        });
        await chooseContext(maker, privacyDomainId);
        api = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
        child = await api(participantPath, {}, true);
        assert.equal(child.status, 200);
        assert.equal(child.body.state, 'RELEASED');
        assert.equal(child.body.revision, '2');
        await checkCoverage(child.body);
        await maker.reload();
        await expect(maker.getByText('Scoped evidence loaded.', { exact: true })).toBeVisible();
        const preservation = maker
          .locator('details > summary')
          .filter({ hasText: /^Retention, preservation and deletion$/u });
        if (
          (await preservation.count()) &&
          (await preservation.locator('..').getAttribute('open')) === null
        ) {
          await preservation.focus();
          await maker.keyboard.press('Enter');
        }
        await expect(
          maker.getByRole('region', { name: 'Preservation holds', exact: true }),
        ).toContainText(participantHold.holdId);
        await maker.keyboard.press('Tab');
        assert.equal(await maker.evaluate(() => document.activeElement?.tagName !== 'BODY'), true);
        assert.deepEqual((await new AxeBuilder({ page: maker }).analyze()).violations, []);
        await maker.screenshot({
          path: join(artifacts, 'source-holds-desktop.png'),
          fullPage: true,
        });
        await maker.setViewportSize({ width: 360, height: 900 });
        assert.equal(
          await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          true,
        );
        await maker.screenshot({
          path: join(artifacts, 'source-holds-mobile.png'),
          fullPage: true,
        });
      },
    );
    process.stdout.write(
      `OPENPC_SOURCE_HOLDS|PASS|verified-source-selectors|root-governance|child-denial|foreign-denial|coverage|release|restart|workbench|active-preservation=${resumedReleasedHold ? 'PRIOR_RUN' : 'PASS'}|source-scope=${privacyDomainId === rootPrivacy ? 'root' : 'child'}|child-custody=${privacyDomainId === rootPrivacy ? 'NOT_EXERCISED' : 'PASS'}\n`,
    );
  } finally {
    await worker.end();
  }
}
