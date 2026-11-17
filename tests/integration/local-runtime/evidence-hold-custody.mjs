import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  governThroughWorkbench,
  withTransactionBrowser,
  readWorkbenchApproval,
} from './transaction-workbench-browser.mjs';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import {
  decodeAdmittedReceipt,
  verifyReceiptCose,
} from '../../../packages/security-kernel/src/index.ts';
import {
  transactionForms,
  transactionFields,
} from '../../../apps/admin-web/lib/transaction-workflow.ts';
import { transactionCandidate } from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';
import { createHttpBusinessSigningProvider } from '../../../services/identity-service/src/domain/http-business-signing-provider.ts';
import { validateBusinessProviderObservation } from '../../../services/identity-service/src/domain/business-signing-provider.ts';

// SEM-059: real initial-trust actors, OIDC/WebAuthn, public governance and packaged custody worker.
const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [
  secretRoot,
  participantId,
  privacyDomainId,
  composeJson,
  fixturePrivacy = privacyDomainId,
  resumeRoot,
] = process.argv.slice(2);
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const root = resumeRoot ?? (await mkdtemp(join(secretRoot, '..', 'data', 'evidence-holds-')));
assert.ok(root.startsWith(join(secretRoot, '..', 'data', 'evidence-holds-')));
const artifacts = join(secretRoot, '..', 'evidence', 'hold-selector-browser');
await mkdir(artifacts, { recursive: true, mode: 0o700 });
const scope = resumeRoot
  ? (({ participantId, privacyDomainId, streamId }) => ({
      participantId,
      privacyDomainId,
      streamId,
    }))(JSON.parse(await readFile(join(root, 'worker.json'), 'utf8')).scopes[0])
  : { participantId, privacyDomainId, streamId: `hold-authentication-${uuidv7()}` };
assert.equal(scope.participantId, participantId);
assert.equal(scope.privacyDomainId, privacyDomainId);
assert.match(scope.streamId, /^hold-authentication-[0-9a-f-]{36}$/u);
const reason = `Preserve exact evidence for independent investigation ${scope.streamId}.`;
const database = { host: '127.0.0.1', port: 55432, database: 'openpc_control' };
const pool = new Pool({
  ...database,
  user: 'openpc_control',
  max: 1,
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
try {
  // Recheck the changed shared governed-input owner against original module evidence.
  // Module admission/install/activation are never repeated for this continuation.
  const moduleInputs = await pool.query(
    `select a.catalog_operation_id,(openpc.check_governed_configuration_receipt(a)).consumed_operation_id=a.operation_id valid
     from control.audit_occurrence a where a.participant_id=$1 and a.privacy_domain_id=$2
     and a.receipt_id in(select distinct on(catalog_operation_id) receipt_id from control.audit_occurrence
      where participant_id=$1 and privacy_domain_id=$2 and catalog_operation_id in('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE')
      order by catalog_operation_id,recorded_at_ns desc)`,
    [participantId, fixturePrivacy],
  );
  assert.equal(moduleInputs.rowCount, 3);
  assert.ok(moduleInputs.rows.every((row) => row.valid));
  const chain = (
    await pool.query(
      'select chain_id,genesis_digest from control.contract_runtime_binding where participant_id=$1 and privacy_domain_id=$2 order by runtime_binding_id limit 1',
      [participantId, fixturePrivacy],
    )
  ).rows[0];
  assert.ok(chain, 'hold forms use the admitted local chain identity');
  const verifyHoldReceipt = async (view, transition) => {
    const operationId =
      transition === 'create' ? view.creationOperationId : view.releaseOperationId;
    const expectedDigest =
      transition === 'create' ? view.creationReceiptDigest : view.releaseReceiptDigest;
    const result = await pool.query(
      `select a.receipt_cbor,a.cose_sign1,a.receipt_digest,k.public_key_spki_der
       from control.audit_occurrence a join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
       where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.aggregate_id=$4
        and a.signer_trust_snapshot_digest=k.trust_digest`,
      [participantId, privacyDomainId, operationId, view.holdId.slice(-36)],
    );
    assert.equal(result.rowCount, 1);
    const row = result.rows[0];
    assert.equal(
      expectedDigest,
      `sha256:${createHash('sha256').update(row.receipt_cbor).digest('hex')}`,
    );
    assert.equal(expectedDigest, `sha256:${row.receipt_digest.toString('hex')}`);
    assert.equal(
      verifyReceiptCose(row.public_key_spki_der, row.receipt_cbor, row.cose_sign1),
      true,
    );
    const receipt = decodeAdmittedReceipt(row.receipt_cbor);
    const family =
      view.selector.type === 'PARTICIPANT' ? 'evidence-participant-hold' : 'evidence-hold';
    assert.equal(receipt.transitionProfileId, `pc.control.${family}.${transition}`);
    assert.equal(receipt.operationId, operationId);
    assert.notEqual(receipt.receiptId, operationId);
    assert.deepEqual(
      receipt.authorizationEvidence.map((proof) => proof.kind),
      [3, 4],
    );
  };
  const container = (
    await exec(compose[0], [...compose.slice(1), 'ps', '-q', 'control-api'])
  ).stdout.trim();
  const actual = JSON.parse((await exec('docker', ['inspect', container])).stdout)[0];
  const built = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  assert.equal(actual.Image, built.Id);
  assert.equal(built.Config.Labels['io.openpc.image.service'], 'control-api');
  await exec('docker', [
    'cp',
    `${container}:/app/evidence-worker.mjs`,
    join(root, 'evidence-worker.mjs'),
  ]);
  const configuration = join(root, 'worker.json');
  const sinkId = resumeRoot
    ? JSON.parse(await readFile(configuration, 'utf8')).sinkId
    : `hold-sink-${uuidv7()}`;
  if (!resumeRoot) {
    await writeFile(join(root, 'key'), randomBytes(32), { mode: 0o600, flag: 'wx' });
    await writeFile(
      configuration,
      JSON.stringify({
        database: {
          ...database,
          user: 'openpc_local_control_worker',
          passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
        },
        vaultDirectory: join(root, 'vault'),
        sinkId,
        scopes: [
          {
            ...scope,
            source: 'AUTHENTICATION',
            activeKeyId: 'hold-test-key',
            keys: [{ keyId: 'hold-test-key', keyFile: join(root, 'key') }],
            retentionSeconds: 86400,
            capacityBytes: 16 * 1024 * 1024,
          },
        ],
      }),
      { mode: 0o600 },
    );
  }
  const retained = resumeRoot
    ? (
        await pool.query(
          `select a.approval_request_id::text as "approvalId",c.candidate_document as candidate,c.maker_principal_id::text as "makerId",
       c.resource_id::text as "resourceId",c.candidate_digest as "candidateDigest"
      from control.mutation_candidate c join control.approval_request a on a.subject_id=c.mutation_candidate_id
       and a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
      where c.participant_id=$1 and c.privacy_domain_id=$2 and c.candidate_document->>'reason'=$3
       and c.catalog_operation_id in ('CFG-OP-CREATE-EVIDENCE-HOLD','CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD')
       and c.predecessor_candidate_id is null order by c.created_at,c.mutation_candidate_id`,
          [participantId, privacyDomainId, reason],
        )
      ).rows
    : [];
  if (resumeRoot) {
    assert.equal(retained.length, 9, 'reconcile all original selector intents');
    const provider = createHttpBusinessSigningProvider({
      origin: 'https://127.0.0.1:53007',
      trustCa: await readFile(join(secretRoot, 'business_provider_ca.pem')),
      certificate: await readFile(join(secretRoot, 'business_api_cert.pem')),
      privateKey: await readFile(join(secretRoot, 'business_api_key.pem')),
    });
    try {
      const attemptId = process.env.OPENPC_HOLD_RECONCILE_ATTEMPT;
      assert.match(
        attemptId ?? '',
        /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      );
      const stored = JSON.parse(
        await readFile(
          join(secretRoot, '..', 'data', 'signing-provider', 'attempts', `${attemptId}.json`),
          'utf8',
        ),
      );
      assert.equal(stored.request.method, 'SIGN_RECEIPT');
      const receipt = decodeAdmittedReceipt(Buffer.from(stored.request.payloadHex, 'hex'));
      assert.equal(receipt.transitionProfileId, 'pc.control.evidence-participant-hold.create');
      assert.equal(receipt.participantId, participantId);
      assert.equal(receipt.privacyDomainId, privacyDomainId);
      assert.equal(receipt.aggregateId, retained[8].resourceId);
      assert.deepEqual(receipt.candidateDigest, retained[8].candidateDigest);
      const observed = await provider.lookup(attemptId);
      assert.ok(observed);
      validateBusinessProviderObservation(stored.request, observed);
      assert.equal(observed?.outcome, 'REJECTED');
      assert.equal(observed?.reason, 'NOT_APPLIED');
      assert.equal(observed?.resultHex, null);
      assert.equal(
        (
          await pool.query(
            'select count(*)::int n from control.audit_occurrence where operation_id=$1',
            [observed.operationId],
          )
        ).rows[0].n,
        0,
      );
      assert.equal(
        (
          await pool.query(
            'select count(*)::int n from control.retention_hold where creation_operation_id=$1',
            [observed.operationId],
          )
        ).rows[0].n,
        0,
      );
      process.stdout.write(
        'OPENPC_HOLD_RECOVERY|PASS|original-provider-not-applied|no-committed-hold-or-receipt\n',
      );
    } finally {
      provider.close();
    }
  }
  const run = () =>
    exec(process.execPath, [join(root, 'evidence-worker.mjs'), '--once'], {
      env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
      timeout: 30000,
      maxBuffer: 65536,
    });
  await run();
  const first = (
    await pool.query(
      `select receipt_digest from control.evidence_catalogue where participant_id=$1
    and privacy_domain_id=$2 and stream_id=$3 order by sequence limit 1`,
      [participantId, privacyDomainId, scope.streamId],
    )
  ).rows[0];
  assert.ok(first, 'pre-existing verified authentication custody is required');
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
        'bootstrap-evidence-hold-selectors',
      ],
      { timeout: 30000, maxBuffer: 65536 },
    );
  const drain = async () => {
    for (let iteration = 0; iteration < 64; iteration++) {
      await run();
      const remaining = (
        await pool.query(
          `select exists(select 1 from control.authentication_occurrence a
        where a.participant_id=$1 and a.privacy_domain_id=$2 and not exists(select 1 from control.evidence_catalogue c
        where c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id and c.stream_id=$3
         and c.record_id=a.occurrence_id::text)) or exists(
          select 1 from control.evidence_segment s where s.participant_id=$1
           and s.privacy_domain_id=$2 and s.stream_id=$3 and (
            not exists(select 1 from control.evidence_checkpoint p where p.participant_id=s.participant_id
             and p.privacy_domain_id=s.privacy_domain_id and p.stream_id=s.stream_id
             and p.segment_id=s.segment_id and p.sink_id=$4)
            or exists(select 1 from control.retention_hold h where h.participant_id=s.participant_id
             and h.privacy_domain_id=s.privacy_domain_id and openpc.evidence_hold_requires_coverage(h,s.stream_id,s.segment_id)
             and not exists(select 1 from control.evidence_hold_coverage c where c.participant_id=h.participant_id
              and c.privacy_domain_id=h.privacy_domain_id and c.retention_hold_id=h.retention_hold_id
              and c.hold_revision=h.revision and c.sink_id=$4 and c.segment_id=s.segment_id)))) pending`,
          [participantId, privacyDomainId, scope.streamId, sinkId],
        )
      ).rows[0].pending;
      if (!remaining) return;
    }
    assert.fail('authentication custody did not drain within its bounded acceptance window');
  };
  await withTransactionBrowser(
    { secretRoot, evidenceRoot: artifacts, artifacts, route: '/operate/evidence', privacyDomainId },
    async ({ maker, checker, actors }) => {
      let createIndex = 0;
      const create = async (fields, participant = false) => {
        const saved = retained[createIndex++];
        if (saved) {
          const kind = participant ? 'evidence-participant-hold' : 'evidence-hold';
          const values = Object.fromEntries(
            Object.entries(fields).map(([label, value]) => {
              const field = transactionForms[kind].fields.find((field) => field.label === label);
              assert.ok(field);
              return [field.name, value];
            }),
          );
          const expected = transactionCandidate(
            kind,
            transactionFields(kind, values),
            reason,
            participantId,
          ).body;
          assert.deepEqual(
            saved.candidate,
            expected,
            'recovery preserves every meaningful original input',
          );
          assert.equal(saved.makerId, actors.maker.principalId);
          let approvalId = saved.approvalId;
          const review = await readWorkbenchApproval(checker, approvalId);
          let completed = await readWorkbenchApproval(maker, approvalId);
          const originalKey = completed.candidate.businessIdempotencyKey;
          if (completed.candidate.operationRef === null) {
            assert.equal(completed.result, null);
            for (let attempt = 0; attempt < 8; attempt++) {
              assert.deepEqual(completed.candidate.candidate, saved.candidate);
              assert.equal(completed.candidate.businessIdempotencyKey, originalKey);
              if (completed.candidate.successorApprovalRef)
                approvalId = completed.candidate.successorApprovalRef.slice(-36);
              else if (completed.candidate.canRequestResume) {
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
                assert.notEqual(approvalId, saved.approvalId);
              } else break;
              completed = await readWorkbenchApproval(maker, approvalId);
            }
            const next = await readWorkbenchApproval(checker, approvalId);
            assert.deepEqual(next.candidate.candidate, saved.candidate);
            assert.equal(
              next.candidate.businessIdempotencyKey,
              null,
              'checker receives no maker replay key',
            );
            if (next.approval.state === 'REQUESTED') {
              await checker
                .getByRole('button', { name: 'Approve with security key', exact: true })
                .click();
              await expect(
                checker.getByText('Independent approval recorded.', { exact: true }),
              ).toBeVisible();
            }
            completed = await readWorkbenchApproval(maker, approvalId);
            assert.equal(completed.candidate.businessIdempotencyKey, originalKey);
            assert.equal(completed.candidate.approvalUsable, true);
            assert.equal(typeof completed.reviewToken, 'string');
            assert.ok(completed.stepUp);
            const execute = maker.getByRole('button', {
              name: 'Execute approved request',
              exact: true,
            });
            await expect(execute).toBeEnabled();
            const [executed] = await Promise.all([
              maker.waitForResponse(
                (response) =>
                  response.request().method() === 'POST' &&
                  new URL(response.url()).pathname === '/api/v1/ui/transaction-workbench' &&
                  response.request().postDataJSON()?.command === 'EXECUTE',
              ),
              execute.click(),
            ]);
            assert.equal(executed.status(), 202);
            await expect(
              maker.getByText(
                'Command readback refreshed. Inspect the operation and effect state below.',
                { exact: true },
              ),
            ).toBeVisible();
            completed = await readWorkbenchApproval(maker, approvalId);
          }
          assert.equal(completed.candidate.state, 'CONSUMED');
          await verifyHoldReceipt(completed.result, 'create');
          return { approvalId, review, completed };
        }
        const created = await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: participant
            ? 'Preserve evidence across a Participant'
            : 'Preserve evidence under a hold',
          fields,
          reason,
        });
        await verifyHoldReceipt(created.completed.result, 'create');
        return created;
      };
      const range = await create({
        'Hold kind': 'LEGAL',
        'Evidence to preserve': 'SEQUENCE_RANGE',
        'Evidence stream to preserve': scope.streamId,
        'First sequence to preserve': '1',
      });
      assert.deepEqual(range.review.candidate.candidate.selector, {
        type: 'SEQUENCE_RANGE',
        streamId: scope.streamId,
        fromSequence: '1',
        throughSequence: null,
      });
      assert.equal(range.completed.result.state, 'ACTIVE');
      assert.equal(range.completed.result.coverage, resumeRoot ? 'VERIFIED' : 'PENDING');
      const rangeRef = range.completed.result.holdId;
      await drain();
      // A fresh receipt is unique to this run's stream. A digest copied into an
      // older retained stream correctly remains pending until that sink responds.
      const receiptRecord = (
        await pool.query(
          `select c.receipt_digest from control.evidence_catalogue c where c.participant_id=$1
           and c.privacy_domain_id=$2 and c.stream_id=$3 and ($4::text is null or c.receipt_digest=$4) and not exists(
            select 1 from control.evidence_catalogue other where other.participant_id=c.participant_id
             and other.privacy_domain_id=c.privacy_domain_id and other.receipt_digest=c.receipt_digest
             and other.stream_id<>c.stream_id) order by c.sequence desc limit 1`,
          [
            participantId,
            privacyDomainId,
            scope.streamId,
            retained[1]?.candidate.selector.recordDigest ?? null,
          ],
        )
      ).rows[0];
      assert.ok(receiptRecord, 'fresh real authentication receipt must be available');
      const refresh = maker.waitForResponse(
        (response) => new URL(response.url()).pathname === '/api/v1/ui/evidence-workbench',
      );
      await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).click();
      assert.equal((await refresh).status(), 200);
      await expect(
        maker.getByRole('region', { name: 'Evidence catalogue', exact: true }),
      ).toContainText(receiptRecord.receipt_digest);
      const receipt = await create({
        'Hold kind': 'INCIDENT',
        'Evidence to preserve': 'DIGEST',
        'Receipt digest': receiptRecord.receipt_digest,
      });
      assert.equal(receipt.completed.result.state, 'ACTIVE');
      await drain();
      const rangeNow = await readWorkbenchApproval(maker, range.approvalId);
      assert.equal(rangeNow.result.coverage, 'VERIFIED');
      assert.equal(
        (await readWorkbenchApproval(maker, receipt.approvalId)).result.coverage,
        'VERIFIED',
      );
      const future = (
        await pool.query(
          `select count(*)::int count from control.evidence_catalogue c
      join control.retention_hold h on h.participant_id=c.participant_id and h.privacy_domain_id=c.privacy_domain_id
      join control.evidence_hold_coverage coverage on coverage.participant_id=h.participant_id
       and coverage.privacy_domain_id=h.privacy_domain_id and coverage.retention_hold_id=h.retention_hold_id
       and coverage.segment_id=c.segment_id and coverage.hold_revision=1
      where h.retention_hold_id=$1 and c.stream_id=$2 and c.occurred_at>h.effective_at`,
          [rangeRef.slice(-36), scope.streamId],
        )
      ).rows[0].count;
      assert.ok(
        future > 0,
        'new real authentication after hold activation must receive preservation coverage',
      );
      // Archive these actual governed hold receipts into an independent stream.
      // This supplies real unresolved business lineage and a separate sink that
      // cannot be acknowledged by the authentication-only worker below.
      const businessConfiguration = join(root, 'business-worker.json');
      const businessConfig = JSON.parse(
        await readFile(resumeRoot ? businessConfiguration : configuration, 'utf8'),
      );
      if (!resumeRoot) {
        businessConfig.sinkId = `${sinkId}-business`;
        businessConfig.vaultDirectory = join(root, 'business-vault');
        businessConfig.scopes[0].source = 'BUSINESS_TRANSITION';
        businessConfig.scopes[0].streamId = `hold-business-${uuidv7()}`;
        await writeFile(businessConfiguration, JSON.stringify(businessConfig), { mode: 0o600 });
        await exec(process.execPath, [join(root, 'evidence-worker.mjs'), '--once'], {
          env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: businessConfiguration },
          timeout: 30000,
          maxBuffer: 65536,
        });
      }
      assert.ok(
        (
          await pool.query(
            `select count(*)::int count from control.evidence_catalogue where participant_id=$1
             and privacy_domain_id=$2 and stream_id=$3 and evidence_class='BUSINESS_TRANSITION'`,
            [participantId, privacyDomainId, businessConfig.scopes[0].streamId],
          )
        ).rows[0].count > 0,
        'unresolved lineage must come from real signed business custody',
      );
      const domain = await create({
        'Hold kind': 'REGULATORY',
        'Evidence to preserve': 'PRIVACY_DOMAIN',
      });
      assert.equal(domain.completed.result.state, 'ACTIVE');
      assert.equal(domain.completed.result.coverage, 'PENDING');
      // This adapter owns one sink/stream. Other retained streams remain explicitly pending.
      await run();
      assert.equal(
        (await readWorkbenchApproval(maker, domain.approvalId)).result.coverage,
        'PENDING',
      );
      // New rules can reserve explicit future identities. Their form/governance
      // acceptance does not claim positive source-lineage or Fact-store coverage.
      const futureProfile =
        retained[4]?.candidate.selector.factProfileId ?? `urn:openpc:fact-profile:${uuidv7()}`;
      const futureResource =
        retained[3]?.candidate.selector.projectionId ?? `urn:openpc:resource:${uuidv7()}`;
      const extended = [];
      for (const fields of [
        { 'Evidence to preserve': 'PROJECTION', 'Projection reference': futureResource },
        {
          'Evidence to preserve': 'FACT_TYPE_KEY',
          'Fact type': 'RELATIONSHIP',
          'Fact profile reference': futureProfile,
        },
        {
          'Evidence to preserve': 'BLOCK_RANGE',
          'Chain ID': chain.chain_id,
          'Genesis digest': chain.genesis_digest,
          'First block to preserve': '9007199254740993',
        },
        {
          'Evidence to preserve': 'GENERATION',
          'Generation kind': 'RUNTIME_CONFIGURATION',
          'Runtime configuration generation reference': futureResource,
        },
        {
          'Evidence to preserve': 'GENERATION',
          'Generation kind': 'CANONICAL_FACT',
          'Fact profile reference': futureProfile,
          'Canonical Fact generation number': '9007199254740993',
        },
      ]) {
        const hold = await create({ 'Hold kind': 'INCIDENT', ...fields });
        assert.equal(hold.completed.result.coverage, 'UNAVAILABLE');
        extended.push(hold.completed.result);
      }
      const participantHold = await create({ 'Hold kind': 'LEGAL' }, true);
      assert.equal(participantHold.completed.result.selector.type, 'PARTICIPANT');
      assert.equal(participantHold.completed.result.governancePrivacyDomainId, privacyDomainId);
      assert.equal(participantHold.completed.result.coveragePrivacyDomainId, privacyDomainId);
      assert.equal(participantHold.completed.result.coverage, 'PENDING');
      await run();
      extended.push(participantHold.completed.result);
      for (const hold of [
        receipt.completed.result,
        range.completed.result,
        domain.completed.result,
        ...extended,
      ]) {
        const ref = hold.holdId;
        const release = await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label:
            hold.selector.type === 'PARTICIPANT'
              ? 'Release a Participant-wide evidence hold'
              : 'Release an evidence hold',
          fields: { 'Resource reference': ref, 'Expected revision': '1' },
          reason: 'Independently release this exact preservation rule without deleting evidence.',
        });
        assert.equal(release.completed.result.state, 'RELEASED');
        assert.equal(release.completed.result.revision, '2');
        assert.equal(
          release.completed.result.coverage,
          hold.coverage === 'UNAVAILABLE' ? 'UNAVAILABLE' : 'PENDING',
        );
        await verifyHoldReceipt(release.completed.result, 'release');
      }
      await drain();
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
      const refreshing = maker.waitForResponse(
        (response) => new URL(response.url()).pathname === '/api/v1/ui/evidence-workbench',
      );
      await maker.getByRole('button', { name: 'Refresh evidence', exact: true }).focus();
      await maker.keyboard.press('Enter');
      assert.equal((await refreshing).status(), 200);
      const holds = maker.getByRole('region', { name: 'Preservation holds', exact: true });
      await expect(holds).toContainText(rangeRef);
      await expect(holds).toContainText('RELEASED');
      const rangeItem = holds.locator('li').filter({ hasText: rangeRef });
      await expect(rangeItem).toContainText('VERIFIED');
      await expect(rangeItem).toContainText(range.completed.result.creationReceiptDigest);
      await expect(rangeItem).toContainText('Release receipt: sha256:');
      await expect(
        holds.locator('li').filter({ hasText: domain.completed.result.holdId }),
      ).toContainText('PENDING');
      const acknowledgements = (
        await pool.query(
          `select hold_revision::text,count(*)::int count from control.evidence_hold_coverage
      where retention_hold_id=$1 group by hold_revision`,
          [rangeRef.slice(-36)],
        )
      ).rows;
      assert.ok(acknowledgements.some((row) => row.hold_revision === '1' && row.count > 0));
      assert.ok(acknowledgements.some((row) => row.hold_revision === '2' && row.count > 0));
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({ path: join(artifacts, 'holds-desktop.png'), fullPage: true });
      await maker.setViewportSize({ width: 360, height: 800 });
      assert.equal(
        await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
        true,
      );
      assert.equal((await new AxeBuilder({ page: maker }).analyze()).violations.length, 0);
      await maker.screenshot({ path: join(artifacts, 'holds-reflow.png'), fullPage: true });
    },
  );
  process.stdout.write(
    'OPENPC_EVIDENCE_HOLDS|PASS|real-governance|eight-selector-forms|both-generation-kinds|participant-scope|existing-and-future|separate-release|signed-transitions|original-module-evidence|packaged-worker|durable-coverage|unknown-lineage-preserved|partial-coverage-truth|restart-readback|keyboard|axe|reflow\n',
  );
} finally {
  await pool.end();
}
