import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  verifyReceiptCose,
  decodeAdmittedReceipt,
} from '../../../packages/security-kernel/src/index.js';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;
const deletionAction = 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1';
const policyAction = 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1';
const urn = (uuid: string) => `urn:openpc:resource:${uuid}`;

// TP-RETENTION-RECOVERY / SEM-059: this batch removes actual local ciphertext,
// preserving independent source and sink custody. All approvals, policy/hold
// transitions and authentication source records reach their real public owners.
integration(
  'deletes one governed local evidence object atomically with actual accounting and a signed restart-safe result',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const runtime = new Pool({
      connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
      max: 1,
    });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'delete-authentication' };
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'evidence-deletion-'));
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const signers: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>>[] = [];
    try {
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
      );
      for (const family of ['retention-policy', 'evidence-hold', 'evidence-deletion'] as const)
        signers.push(
          await evidenceGovernanceSigningFixture(
            admin,
            scope.participantId,
            scope.privacyDomainId,
            family,
          ),
        );
      const [policySigner, holdSigner, deletionSigner] = signers;
      const participantId = `urn:openpc:participant:${scope.participantId}`;
      // Initial-trust sessions are not authentication receipts. This independent
      // RAW_SOURCE_BODY policy reaches real public WebAuthn owners and creates
      // source occurrences without supplying an AUDIT_EVIDENCE retention policy.
      await fixture.restartConfiguration(policySigner!.evidence);
      await fixture.create('retention-policies', policyAction, {
        participantId,
        predecessorPolicyId: null,
        policy: {
          dataClass: 'RAW_SOURCE_BODY',
          policyVersion: '1.0.0',
          retentionPeriodMs: '0',
          localGraceMs: '0',
          sinkQuorum: 0,
          deletionMode: 'ROW_DELETE',
          makerCheckerRequired: true,
        },
      });
      const sourceCount = await admin.query(
        `select count(*)::int n from control.authentication_occurrence
        where participant_id=$1 and privacy_domain_id=$2 and method='WEBAUTHN_ASSERTION'`,
        [scope.participantId, scope.privacyDomainId],
      );
      expect(sourceCount.rows[0].n).toBeGreaterThanOrEqual(2);
      const custody = new EvidenceCustody(worker),
        encryption = { keyId: 'deletion-test-key', key: randomBytes(32) };
      // Initial storage promise is explicit and already elapsed, not rewritten by deletion.
      const retentionUntil = new Date(Date.now() - 1000)
        .toISOString()
        .replace(/\.(\d{3})Z$/u, '.$1000Z');
      const admitted = await custody.ingestAuthentication(
        scope,
        encryption,
        retentionUntil,
        1048576,
      );
      expect(admitted).not.toBeNull();
      const segmentId = admitted!.segmentId;
      const records = await admin.query(
        `select evidence_id::text id from control.evidence_catalogue
      where participant_id=$1 and segment_id=$2 order by sequence`,
        [scope.participantId, segmentId],
      );
      expect(records.rows.length).toBeGreaterThanOrEqual(2);
      const recordRef = urn(records.rows[0].id);
      const plan = (record = recordRef) =>
        fixture!.read(`evidence-records/${record}/deletion-plan`);
      expect(await plan()).toMatchObject({
        status: 200,
        body: {
          eligible: false,
          blockers: expect.arrayContaining(['NO_ACTIVE_POLICY', 'INCOMPLETE_CHECKPOINT']),
        },
      });
      const sink = await LocalEvidenceVault.open(join(root, 'archive'), 'deletion-archive');
      await custody.exportNext(scope, sink);
      const stored = (
        await admin.query(
          `select receipt from control.evidence_checkpoint where participant_id=$1 and segment_id=$2`,
          [scope.participantId, segmentId],
        )
      ).rows[0].receipt;
      const originalBytes = await sink.read(stored.object);
      const original = openSegment(
        originalBytes,
        admitted!.objectDigest,
        inspectSegment(originalBytes).header,
        encryption.key,
      );
      expect(
        original.records.every(
          (record) =>
            record.evidenceClass === 'AUTHENTICATION' &&
            record.sourceFormat === 'OPENPC_AUTHENTICATION_OCCURRENCE_V1',
        ),
      ).toBe(true);
      await fixture.restartConfiguration(policySigner!.evidence);
      await fixture.create('retention-policies', policyAction, {
        participantId,
        predecessorPolicyId: null,
        policy: {
          dataClass: 'AUDIT_EVIDENCE',
          policyVersion: '1.0.0',
          retentionPeriodMs: '0',
          localGraceMs: '0',
          sinkQuorum: 1,
          deletionMode: 'ROW_DELETE',
          makerCheckerRequired: true,
        },
      });
      const eligible = await plan();
      expect(eligible).toMatchObject({
        status: 200,
        body: { eligible: true, blockers: [], localPayload: 'RETAINED' },
      });
      const fields = {
        participantId,
        selection: eligible.body.selection,
        beforeDigest: eligible.body.beforeDigest,
      };
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const prepared = await fixture.prepareMutation(
        'evidence-deletions',
        deletionAction,
        fields,
        true,
      );
      expect((await prepared.commit()).status).toBe(403);
      // A hold added after approval is rechecked, even before its sink coverage exists.
      await fixture.restartConfiguration(holdSigner!.evidence);
      const held = await fixture.create('evidence-holds', 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1', {
        participantId,
        holdKind: 'LEGAL',
        selector: {
          type: 'SEQUENCE_RANGE',
          streamId: scope.streamId,
          fromSequence: '1',
          throughSequence: null,
        },
      });
      expect(await plan()).toMatchObject({ body: { eligible: false, blockers: ['ACTIVE_HOLD'] } });
      expect(await fixture.read(`evidence-holds/${String(held.body.resourceRef)}`)).toMatchObject({
        body: { coverage: 'PENDING' },
      });
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await prepared.stepUp();
      expect((await prepared.commit()).status).toBe(412);
      await fixture.restartConfiguration(holdSigner!.evidence);
      await fixture.create(
        `evidence-holds/${String(held.body.resourceRef)}/release`,
        'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
        {
          targetRef: held.body.resourceRef,
          expectedRevision: '1',
        },
      );
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const snapshot = async () =>
        (
          await admin.query(
            `select
      (select count(*)::int from control.evidence_segment_payload where participant_id=$1) payloads,
      (select count(*)::int from control.deletion_job where participant_id=$1) jobs,
      (select count(*)::int from control.evidence_deletion_item where participant_id=$1) items,
      (select count(*)::int from control.audit_occurrence where participant_id=$1) receipts,
      (select count(*)::int from control.receipt_signing_attempt where participant_id=$1) attempts,
      (select count(*)::int from control.outbox_event where participant_id=$1) events,
      (select used_bytes::text from control.evidence_stream where participant_id=$1 and stream_id=$2) used`,
            [scope.participantId, scope.streamId],
          )
        ).rows[0];
      await prepared.stepUp();
      const before = await snapshot();
      for (const mode of ['UNAVAILABLE', 'CORRUPT'] as const) {
        deletionSigner!.faults.mode = mode;
        const calls = deletionSigner!.faults.calls;
        expect((await prepared.commit()).status).toBeGreaterThanOrEqual(400);
        expect(deletionSigner!.faults.calls).toBe(calls + 1);
        expect(await snapshot()).toEqual(before);
      }
      deletionSigner!.faults.mode = undefined;
      const committed = await prepared.commit();
      expect(committed, JSON.stringify(committed)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED', truthState: 'SUCCESS' },
      });
      const resultRef = String(committed.body.resourceRef),
        jobId = resultRef.slice(-36);
      const result = await fixture.read(`evidence-deletions/${resultRef}`);
      expect(result).toMatchObject({
        status: 200,
        body: {
          state: 'SUCCEEDED',
          revision: '1',
          selection: fields.selection,
          deletedCount: '1',
          deletedBytes: String(originalBytes.length),
          retainedAliasCount: '0',
          externalAttemptState: 'NOT_STARTED',
          beforeDigest: fields.beforeDigest,
        },
      });
      const after = await snapshot();
      expect(after).toMatchObject({
        payloads: before.payloads - 1,
        jobs: 1,
        items: 1,
        receipts: before.receipts + 1,
        attempts: before.attempts + 1,
        used: String(BigInt(before.used) - BigInt(originalBytes.length)),
      });
      expect(after.events).toBe(before.events + 1);
      const receipt = (
        await admin.query(
          `select receipt_cbor,cose_sign1,receipt_digest from control.audit_occurrence
      where participant_id=$1 and aggregate_id=$2 and aggregate_type='evidence-deletion'`,
          [scope.participantId, jobId],
        )
      ).rows[0];
      expect(
        verifyReceiptCose(deletionSigner!.publicKey, receipt.receipt_cbor, receipt.cose_sign1),
      ).toBe(true);
      expect(decodeAdmittedReceipt(receipt.receipt_cbor)).toMatchObject({
        transitionProfileId: 'pc.control.evidence-deletion.local',
        operationId: committed.body.operationId,
        aggregateId: jobId,
        before: { existence: 0, revision: 0n },
        after: { existence: 1, revision: 1n },
      });
      expect(result.body.receiptDigest).toBe(`sha256:${receipt.receipt_digest.toString('hex')}`);
      expect(await plan()).toMatchObject({
        status: 200,
        body: {
          localPayload: 'DELETED',
          eligible: false,
          blockers: ['ALREADY_DELETED'],
          selection: null,
          beforeDigest: null,
        },
      });
      expect((await prepared.commit()).body).toEqual(committed.body);
      await fixture.restartConfiguration();
      expect((await prepared.commit()).body).toEqual(committed.body);
      expect((await fixture.read(`evidence-deletions/${resultRef}`)).body).toEqual(result.body);
      expect(await snapshot()).toEqual(after);
      expect(await sink.read(stored.object)).toEqual(originalBytes);
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.evidence_catalogue where participant_id=$1 and segment_id=$2`,
            [scope.participantId, segmentId],
          )
        ).rows[0].n,
      ).toBe(records.rows.length);
      for (const record of original.records)
        expect(
          (
            await admin.query(
              'select receipt from control.authentication_occurrence where occurrence_id=$1',
              [record.recordId],
            )
          ).rows[0].receipt,
        ).toEqual(Buffer.from(record.receiptBase64, 'base64'));
      // Replay never resurrects removed bytes or reports them as still in local custody.
      await expect(
        custody.admit(
          scope,
          original.records.map((record) => ({
            recordId: record.recordId,
            evidenceClass: record.evidenceClass,
            sourceFormat: record.sourceFormat,
            occurredAt: record.occurredAt,
            receiptDigest: record.receiptDigest,
            receiptBase64: record.receiptBase64,
          })),
          encryption,
          retentionUntil,
          1048576,
        ),
      ).rejects.toMatchObject({ code: 'CONFLICT' });
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect((await foreign.read(`evidence-deletions/${resultRef}`)).status).toBe(404);
      expect((await foreign.read(`evidence-records/${recordRef}/deletion-plan`)).status).toBe(404);
      // SQL roles cannot assert an effect directly or mutate completed accounting.
      const direct = await runtime.connect();
      for (const statement of [
        'select encrypted_segment from control.evidence_segment_payload',
        `update control.evidence_stream set used_bytes=used_bytes+1 where participant_id=$1`,
        `delete from control.evidence_deletion_item where participant_id=$1`,
        `update control.deletion_job set state='EXECUTING',revision=0 where participant_id=$1`,
      ]) {
        try {
          await direct.query('begin');
          await direct.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
            scope.participantId,
            scope.privacyDomainId,
            id(),
            deletionAction,
          ]);
          await expect(
            direct.query(statement, statement.includes('$1') ? [scope.participantId] : []),
          ).rejects.toThrow();
        } finally {
          await direct.query('rollback');
        }
      }
      direct.release();
      // A fresh object can still be admitted and archived across the retained chain.
      await fixture.refresh();
      const next = await custody.ingestAuthentication(scope, encryption, retentionUntil, 1048576);
      expect(BigInt(next!.firstSequence)).toBe(BigInt(admitted!.throughSequence) + 1n);
      expect(await custody.exportNext(scope, sink)).toMatchObject({ segmentId: next!.segmentId });
      // Competing distinct record selections of this one object physically wait on
      // the shared lifecycle fence, then one succeeds and one observes deletion.
      const nextRecords = (
        await admin.query(
          `select evidence_id::text id from control.evidence_catalogue where participant_id=$1 and segment_id=$2 order by sequence`,
          [scope.participantId, next!.segmentId],
        )
      ).rows;
      const contenders = [];
      for (const record of nextRecords.slice(0, 2)) {
        const candidate = await plan(urn(record.id));
        expect(candidate.body.eligible).toBe(true);
        contenders.push(
          await fixture.prepareMutation(
            'evidence-deletions',
            deletionAction,
            {
              participantId,
              selection: candidate.body.selection,
              beforeDigest: candidate.body.beforeDigest,
            },
            true,
          ),
        );
      }
      expect(contenders).toHaveLength(2);
      for (const contender of contenders) await contender.stepUp();
      const barrier = await admin.connect();
      let pending: Promise<Awaited<ReturnType<(typeof contenders)[0]['commit']>>[]> | undefined;
      try {
        await barrier.query('begin');
        await barrier.query(
          `select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0)), $2::uuid`,
          [scope.participantId, scope.privacyDomainId],
        );
        pending = Promise.all(contenders.map((contender) => contender.commit()));
        let waiting = 0;
        for (let attempt = 0; attempt < 60 && waiting < 2; attempt++) {
          waiting = (
            await admin.query(
              `select count(*)::int n from pg_stat_activity where wait_event='advisory' and query like '%pg_advisory_xact_lock%' and pid<>pg_backend_pid()`,
            )
          ).rows[0].n;
          if (waiting < 2) await delay(10);
        }
        expect(waiting).toBeGreaterThanOrEqual(2);
        await barrier.query('commit');
        const results = await pending;
        expect(results.map((item) => item.status).sort()).toEqual([202, 412]);
      } finally {
        await barrier.query('rollback');
        barrier.release();
        if (pending) await pending;
      }
      expect((await snapshot()).jobs).toBe(2);
    } finally {
      await foreign?.close();
      await fixture?.close();
      for (const signer of signers) signer.close();
      await runtime.end();
      await worker.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  180000,
);
