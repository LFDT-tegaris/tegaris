import './rpc-retirement-signing-cases.js';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  decodeAdmittedReceipt,
  verifyReceiptCose,
} from '../../../packages/security-kernel/src/index.js';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import {
  evidenceGovernanceSigningFixture,
  evidenceGovernanceProfiles,
} from './evidence-governance-signing-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;
const action = 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1';
const policyAction = 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1';
const urn = (value: string) => `urn:openpc:resource:${value}`;

it('validates exact evidence signing inputs before database allocation', () => {
  expect(
    evidenceGovernanceProfiles('evidence-deletion').map((p) => [
      p.catalogOperationId,
      p.profileVersion,
    ]),
  ).toEqual([
    ['CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH', 1],
    ['CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH', 2],
    ['CFG-OP-DELETE-LOCAL-EVIDENCE', 1],
    ['CFG-OP-DELETE-LOCAL-EVIDENCE', 2],
    ['CFG-OP-DELETE-PROJECTION-BATCH', 1],
    ['CFG-OP-DELETE-PROJECTION-BATCH', 2],
    ['CFG-OP-DELETE-PROJECTION-BATCH', 3],
    ['CFG-OP-DELETE-RAW-PROOF-BATCH', 1],
  ]);
  for (const family of ['evidence-hold', 'retention-policy'] as const)
    evidenceGovernanceProfiles(family);
});

integration(
  'fences RPC completion witnesses at the SQL owner before any physical effect',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 1 });
    try {
      const digest = `sha256:${'a'.repeat(64)}`;
      const p = {
        decisionId: id(),
        targetRuntimeId: id(),
        spoolId: 'closure-test',
        capsuleDigest: digest,
        reservedAtNs: '1',
        occurredAtNs: '1',
        sourceSequence: '1',
        sourceDigest: digest,
        activation: { receiptDigest: digest },
        transition: { phase: 'RESERVED', requestDigest: digest },
      };
      const identity = (await pool.query('select openpc.rpc_retirement_identity($1) digest', [p]))
        .rows[0].digest;
      const w = {
        identityDigest: identity,
        terminalSequence: '3',
        terminalOccurredAtNs: '2',
        terminalPhase: 'RELEASED',
        terminalEffect: null,
        terminalDecisionDigest: digest,
        terminalSourceDigest: digest,
        terminalProjectionDigest: digest,
      };
      const check = async (source: unknown, proof: unknown) =>
        (await pool.query('select openpc.rpc_projection_closed_by($1,$2) closed', [source, proof]))
          .rows[0].closed;
      expect(await check(p, w)).toBe(true);
      for (const changed of [
        { terminalSequence: '0' },
        { terminalOccurredAtNs: '0' },
        { identityDigest: `sha256:${'b'.repeat(64)}` },
        { terminalPhase: 'OPERATION_STATUS_RELEASED' },
        { terminalPhase: 'COMMITTED', terminalEffect: 'WRITE_AMBIGUITY' },
      ])
        expect(await check(p, { ...w, ...changed })).toBe(false);
      for (const phase of ['OPERATION_STATUS_RELEASED', 'SOURCE_READ_STARTED'])
        expect(await check({ ...p, transition: { ...p.transition, phase } }, w)).toBe(false);
      const committed = {
        ...p,
        transition: {
          ...p.transition,
          phase: 'COMMITTED',
          decisionEffect: 'ALLOW_FORWARD',
          decisionDigest: digest,
        },
      };
      expect(await check(committed, w)).toBe(true);
      expect(
        await check(committed, { ...w, terminalDecisionDigest: `sha256:${'b'.repeat(64)}` }),
      ).toBe(false);
      expect(
        await check(
          {
            ...committed,
            transition: { ...committed.transition, decisionEffect: 'WRITE_AMBIGUITY' },
          },
          w,
        ),
      ).toBe(false);
    } finally {
      await pool.end();
    }
  },
);

// SEM-059 / TP-RETENTION-RECOVERY: actual WebAuthn producer, public independent
// class policy, live source references, physical projection retirement and its
// signed continuation. This does not claim other catalogue source adapters.
integration.each(['authentication', 'retention-policy'] as const)(
  'retires real %s search projections without source loss or restart resurrection',
  async (producer) => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const runtime = new Pool({
      connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
      max: 1,
    });
    const scope = {
      participantId: id(),
      privacyDomainId: id(),
      streamId: `projection-${producer}`,
    };
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'projection-deletion-'));
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let holdActor: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
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
      const policies = new Map<string, { ref: string; version: number }>();
      const policy = async (dataClass: string, change: Record<string, unknown> = {}) => {
        await fixture!.restartConfiguration(policySigner!.evidence);
        const prior = policies.get(dataClass);
        if (prior)
          await fixture!.create(
            `retention-policies/${prior.ref}/retire`,
            'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1',
            { targetRef: prior.ref, expectedRevision: '1' },
          );
        const version = (prior?.version ?? 0) + 1;
        const result = await fixture!.create('retention-policies', policyAction, {
          participantId,
          predecessorPolicyId: prior?.ref ?? null,
          policy: {
            dataClass,
            policyVersion: `${version}.0.0`,
            retentionPeriodMs: '0',
            localGraceMs: '0',
            sinkQuorum: 1,
            deletionMode:
              dataClass === 'AUDIT_EVIDENCE' || dataClass === 'RAW_SOURCE_BODY'
                ? 'ROW_DELETE'
                : 'PROJECTION_DELETE',
            makerCheckerRequired: true,
            ...change,
          },
        });
        policies.set(dataClass, { ref: String(result.body.resourceRef), version });
      };
      // This independent public operation produces real authentication occurrences.
      await policy('RAW_SOURCE_BODY');
      if (producer === 'retention-policy') await policy('RAW_SOURCE_BODY');
      const custody = new EvidenceCustody(worker);
      const encryption = { keyId: 'projection-test-key', key: randomBytes(32) };
      const retentionUntil = new Date(Date.now() - 1000)
        .toISOString()
        .replace(/\.(\d{3})Z$/u, '.$1000Z');
      const ingest =
        producer === 'authentication'
          ? custody.ingestAuthentication.bind(custody)
          : custody.ingestBusiness.bind(custody);
      const admitted = await ingest(scope, encryption, retentionUntil, 1048576);
      expect(admitted).not.toBeNull();
      const records = (
        await admin.query<{ id: string; record_id: string }>(
          `select evidence_id::text id,record_id from control.evidence_catalogue where participant_id=$1 and segment_id=$2 order by record_id`,
          [scope.participantId, admitted!.segmentId],
        )
      ).rows;
      expect(records.length).toBeGreaterThanOrEqual(2);
      const recordRef = urn(records[0]!.id);
      // A source label or fabricated closed-RPC shape cannot replace a real
      // normalized retirement, its consumed candidate and signed receipt.
      for (const change of [
        {},
        { evidence_class: 'EFFECT', source_format: 'OPENPC_RPC_DECISION_TRANSITION_V1' },
        {
          evidence_class: 'EFFECT',
          source_format: 'OPENPC_RPC_DECISION_TRANSITION_V1',
          record_id: id(),
          receipt_digest: `sha256:${'a'.repeat(64)}`,
        },
      ]) {
        const proof = await admin.query(
          `select openpc.rpc_retired_catalogue_proof(jsonb_populate_record(null::control.evidence_catalogue,to_jsonb(c)||$2::jsonb)) proof
           from control.evidence_catalogue c where evidence_id=$1`,
          [records[0]!.id, change],
        );
        expect(proof.rows).toEqual([{ proof: null }]);
      }

      if (producer === 'retention-policy') {
        const metadata = async (change: Record<string, unknown>) =>
          (
            await admin.query(
              `select openpc.retention_policy_receipt_hold_metadata(
              jsonb_populate_record(null::control.evidence_catalogue,to_jsonb(c)||$2::jsonb)) metadata
             from control.evidence_catalogue c where evidence_id=$1`,
              [records[0]!.id, change],
            )
          ).rows[0].metadata;
        expect(await metadata({})).toMatchObject({ facts: [], projections: [], blocks: [] });
        for (const change of [
          { receipt_digest: `sha256:${'a'.repeat(64)}` },
          { record_id: id() },
          { participant_id: id() },
          { privacy_domain_id: id() },
          { occurred_at: '2000-01-01T00:00:00Z' },
          { evidence_class: 'AUTHENTICATION' },
          { source_format: 'COSE_SIGN1_24001_UNKNOWN_338' },
        ])
          expect(await metadata(change)).toBeNull();
      }
      const plan = async (ref = recordRef) => {
        const response = await fixture!.read(
          `evidence-records/${ref}/search-projection-deletion-plan`,
        );
        expect(response.headers.get('cache-control')).toBe('no-store');
        return response;
      };
      const normalizedDenied = await fixture.read(
        `evidence-records/${recordRef}/normalized-projection-deletion-plan`,
      );
      expect(normalizedDenied.headers.get('cache-control')).toBe('no-store');
      const absentContinuation = await fixture.read(
        `evidence-deletions/${urn(id())}/projection-continuation-plan`,
      );
      expect(absentContinuation.status).toBe(404);
      expect(absentContinuation.headers.get('cache-control')).toBe('no-store');
      expect(await plan()).toMatchObject({
        status: 200,
        body: {
          eligible: false,
          blockers: expect.arrayContaining([
            'NO_ACTIVE_POLICY',
            'REFERENCES',
            'INCOMPLETE_CHECKPOINT',
          ]),
        },
      });
      const sink = await LocalEvidenceVault.open(join(root, 'archive'), 'projection-archive');
      await custody.exportNext(scope, sink);
      const checkpoint = (
        await admin.query(
          `select receipt from control.evidence_checkpoint where participant_id=$1 and segment_id=$2`,
          [scope.participantId, admitted!.segmentId],
        )
      ).rows[0].receipt;
      const archived = await sink.read(checkpoint.object);
      const original = openSegment(
        archived,
        admitted!.objectDigest,
        inspectSegment(archived).header,
        encryption.key,
      );
      await policy('NORMALIZED_JSON_PROJECTION');
      expect(await plan()).toMatchObject({
        body: { blockers: expect.arrayContaining(['NO_ACTIVE_POLICY']) },
      });
      expect(
        await fixture.read(`evidence-records/${recordRef}/normalized-projection-deletion-plan`),
      ).toMatchObject({
        status: 200,
        body: {
          eligible: false,
          projectionState: 'UNAVAILABLE',
          blockers: expect.arrayContaining(['UNSUPPORTED_SOURCE']),
        },
      });
      await policy('SEARCH_PROJECTION');
      expect(await plan()).toMatchObject({ body: { eligible: false, blockers: ['REFERENCES'] } });
      // Clearance comes from an independently governed physical ciphertext effect.
      await policy('AUDIT_EVIDENCE');
      const payloadPlan = await fixture.read(`evidence-records/${recordRef}/deletion-plan`);
      expect(payloadPlan.body.eligible).toBe(true);
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await fixture.create('evidence-deletions', 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1', {
        participantId,
        selection: payloadPlan.body.selection,
        beforeDigest: payloadPlan.body.beforeDigest,
      });
      await policy('SEARCH_PROJECTION', { sinkQuorum: 2 });
      expect(await plan()).toMatchObject({ body: { eligible: false, blockers: ['SINK_QUORUM'] } });
      await policy('SEARCH_PROJECTION', { retentionPeriodMs: '9223372036854775807' });
      expect(await plan()).toMatchObject({
        body: { eligible: false, blockers: ['RETENTION_NOT_ELAPSED'] },
      });
      await policy('SEARCH_PROJECTION', { localGraceMs: '9223372036854775807' });
      expect(await plan()).toMatchObject({
        body: { eligible: false, blockers: ['RETENTION_NOT_ELAPSED'] },
      });
      await policy('SEARCH_PROJECTION');
      const ready = await plan();
      expect(ready).toMatchObject({
        status: 200,
        body: { eligible: true, blockers: [], continuationState: 'READY' },
      });
      expect(ready.body.selection.targets).toHaveLength(records.length);
      expect(ready.body.selection.sourceKind).toBe(
        producer === 'authentication' ? 'AUTHENTICATION_CATALOGUE' : 'RETENTION_POLICY_CATALOGUE',
      );
      const fields = {
        participantId,
        selection: ready.body.selection,
        beforeDigest: ready.body.beforeDigest,
      };
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const prepared = await fixture.prepareMutation(
        'evidence-deletions/projection-batches',
        action,
        fields,
        true,
      );
      const candidateId = String((await fixture.approvalRead(prepared.approvalId)).body.attemptId);
      const noEffect = async (privacy = scope.privacyDomainId) => {
        const client = await runtime.connect();
        try {
          await client.query('begin');
          await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
            scope.participantId,
            privacy,
            fixture!.makerId,
            'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
          ]);
          await client.query('select openpc.assert_mutation_resume_no_effect($1)', [candidateId]);
        } catch (error) {
          const failure = error as { message: string; where?: string };
          throw new Error(`${failure.message}: ${failure.where ?? 'no SQL location'}`);
        } finally {
          await client.query('rollback');
          client.release();
        }
      };
      // The recovery context cannot read protected authentication source rows.
      // Proving no local effect must preserve that distinct disclosure boundary.
      const grantsPath =
        '../../../services/identity-service/src/db/authentication-occurrence-guards.mjs';
      const grants: Record<string, unknown> = await import(grantsPath);
      expect(typeof grants.authenticationOccurrenceGrantsSql).toBe('string');
      const checkedSource = await admin.connect();
      try {
        await checkedSource.query('begin');
        await checkedSource.query(String(grants.authenticationOccurrenceGrantsSql));
        await checkedSource.query('set local role openpc_control_runtime');
        await checkedSource.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`,
          [scope.participantId, scope.privacyDomainId, id(), action],
        );
        expect(
          (
            await checkedSource.query(
              'select count(*)::int n from control.authentication_occurrence where participant_id=$1',
              [scope.participantId],
            )
          ).rows[0].n,
        ).toBeGreaterThanOrEqual(records.length);
        await checkedSource.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`,
          [
            scope.participantId,
            scope.privacyDomainId,
            id(),
            'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
          ],
        );
        expect(
          (
            await checkedSource.query(
              'select count(*)::int n from control.authentication_occurrence where participant_id=$1',
              [scope.participantId],
            )
          ).rows[0].n,
        ).toBe(0);
      } finally {
        await checkedSource.query('rollback');
        checkedSource.release();
      }
      await noEffect();
      await expect(noEffect(id())).rejects.toThrow();
      expect((await prepared.commit()).status).toBe(403);
      // Queue the hold ahead of deletion on the shared physical lifecycle fence.
      // Separate actors isolate authenticator counters and mutable request state.
      holdActor = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
        { existingScope: true, businessEvidence: holdSigner!.evidence },
      );
      const holdIntent = await holdActor.prepareMutation(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId,
          holdKind: 'LEGAL',
          selector: {
            type: 'SEQUENCE_RANGE',
            streamId: scope.streamId,
            fromSequence: '1',
            throughSequence: null,
          },
        },
      );
      await holdIntent.stepUp();
      await prepared.stepUp();
      const barrier = await admin.connect();
      let held: Awaited<ReturnType<typeof holdIntent.commit>>;
      let pendingHold: ReturnType<typeof holdIntent.commit> | undefined;
      let pendingDelete: ReturnType<typeof prepared.commit> | undefined;
      const waitForContenders = async (count: number) => {
        let waiting = 0;
        for (let attempt = 0; attempt < 100 && waiting < count; attempt++) {
          waiting = (
            await admin.query(
              `select count(*)::int n from pg_stat_activity where wait_event='advisory' and query like '%pg_advisory_xact_lock%' and pid<>pg_backend_pid()`,
            )
          ).rows[0].n;
          if (waiting < count) await delay(10);
        }
        expect(waiting).toBeGreaterThanOrEqual(count);
      };
      try {
        await barrier.query('begin');
        await barrier.query(
          `select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))`,
          [scope.participantId],
        );
        pendingHold = holdIntent.commit();
        await waitForContenders(1);
        pendingDelete = prepared.commit();
        await waitForContenders(2);
        await barrier.query('commit');
        held = await pendingHold;
        expect(held.status).toBe(202);
        expect((await pendingDelete).status).toBe(412);
      } finally {
        await barrier.query('rollback');
        barrier.release();
        if (pendingHold) await pendingHold;
        if (pendingDelete) await pendingDelete;
      }
      expect(await plan()).toMatchObject({ body: { eligible: false, blockers: ['ACTIVE_HOLD'] } });
      await fixture.restartConfiguration(holdSigner!.evidence);
      await fixture.create(
        `evidence-holds/${held.body.resourceRef}/release`,
        'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
        { targetRef: held.body.resourceRef, expectedRevision: '1' },
      );
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await prepared.stepUp();
      const snapshot = async () =>
        (
          await admin.query(
            `select
      (select count(*)::int from control.evidence_catalogue where participant_id=$1 and segment_id=$2) projections,
      (select count(*)::int from control.evidence_projection_retirement where participant_id=$1) retirements,
      (select count(*)::int from control.deletion_job where participant_id=$1) jobs,
      (select count(*)::int from control.audit_occurrence where participant_id=$1) receipts,
      (select count(*)::int from control.receipt_signing_attempt where participant_id=$1) attempts,
      (select count(*)::int from control.outbox_event where participant_id=$1) events`,
            [scope.participantId, admitted!.segmentId],
          )
        ).rows[0];
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
      await expect(noEffect()).rejects.toThrow('PC-POLICY-2004');
      const firstRef = String(committed.body.resourceRef);
      const firstRead = await fixture.read(`evidence-deletions/${firstRef}`);
      expect(firstRead).toMatchObject({
        status: 200,
        body: {
          state: 'SUCCEEDED',
          deletedCount: '1',
          deletedBytes: String(ready.body.selection.projectionBytes),
          externalAttemptState: 'NOT_STARTED',
          selection: fields.selection,
        },
      });
      const receipt = (
        await admin.query(
          `select receipt_cbor,cose_sign1,receipt_digest from control.audit_occurrence where participant_id=$1 and aggregate_type='evidence-deletion' and aggregate_id=$2`,
          [scope.participantId, firstRef.slice(-36)],
        )
      ).rows[0];
      expect(
        verifyReceiptCose(deletionSigner!.publicKey, receipt.receipt_cbor, receipt.cose_sign1),
      ).toBe(true);
      expect(decodeAdmittedReceipt(receipt.receipt_cbor)).toMatchObject({
        transitionProfileId: 'pc.control.evidence-deletion.projection',
        transitionProfileVersion: producer === 'retention-policy' ? 2 : 1,
        aggregateId: firstRef.slice(-36),
        operationId: committed.body.operationId,
      });
      expect(firstRead.body.receiptDigest).toBe(`sha256:${receipt.receipt_digest.toString('hex')}`);
      await expect(
        admin.query(
          `select openpc.assert_evidence_deletion_receipt(jsonb_populate_record(null::control.audit_occurrence,
          to_jsonb(a)||jsonb_build_object('profile_version',$3::bigint))) from control.audit_occurrence a
         where participant_id=$1 and aggregate_type='evidence-deletion' and aggregate_id=$2`,
          [scope.participantId, firstRef.slice(-36), producer === 'retention-policy' ? 1 : 2],
        ),
      ).rejects.toThrow('DATA-6021-RECEIPT-ACTUAL-DELETION-STATE');
      expect(await snapshot()).toEqual({
        projections: before.projections - 1,
        retirements: before.retirements + 1,
        jobs: before.jobs + 1,
        receipts: before.receipts + 1,
        attempts: before.attempts + 1,
        events: before.events + 1,
      });
      expect(await plan()).toMatchObject({
        body: { projectionState: 'RETIRED', eligible: false, blockers: ['ALREADY_DELETED'] },
      });
      expect((await fixture.read(`evidence-records/${recordRef}/provenance`)).status).toBe(404);
      // Simulate a discarded commit acknowledgement: replay uses the original intent.
      expect((await prepared.commit()).body).toEqual(committed.body);
      await fixture.restartConfiguration();
      expect((await prepared.commit()).body).toEqual(committed.body);
      expect((await fixture.read(`evidence-deletions/${firstRef}`)).body).toEqual(firstRead.body);
      let previousRef = firstRef;
      for (let index = 1; index < records.length; index++) {
        const next = await fixture.read(
          `evidence-deletions/${previousRef}/projection-continuation-plan`,
        );
        expect(next).toMatchObject({
          status: 200,
          body: {
            eligible: true,
            continuationState: 'READY',
            selection: {
              batchIndex: index,
              priorCursor: { deletionJobId: previousRef },
              targets: fields.selection.targets,
            },
          },
        });
        const result = await fixture.create('evidence-deletions/projection-batches', action, {
          participantId,
          selection: next.body.selection,
          beforeDigest: next.body.beforeDigest,
        });
        const nextRef = String(result.body.resourceRef);
        expect(
          await fixture.read(`evidence-deletions/${previousRef}/projection-continuation-plan`),
        ).toMatchObject({
          body: { eligible: false, continuationState: 'ADVANCED', nextDeletionJobId: nextRef },
        });
        previousRef = nextRef;
      }
      expect(
        await fixture.read(`evidence-deletions/${previousRef}/projection-continuation-plan`),
      ).toMatchObject({
        body: { eligible: false, continuationState: 'COMPLETE', selection: null },
      });
      expect((await snapshot()).projections).toBe(0);
      expect(await sink.read(checkpoint.object)).toEqual(archived);
      for (const record of original.records)
        expect(
          (
            await admin.query(
              producer === 'authentication'
                ? 'select receipt from control.authentication_occurrence where occurrence_id=$1'
                : 'select a.cose_sign1 receipt from control.evidence_record e join control.audit_occurrence a using(participant_id,privacy_domain_id,receipt_id) where e.evidence_record_id=$1',
              [record.recordId],
            )
          ).rows[0].receipt,
        ).toEqual(Buffer.from(record.receiptBase64, 'base64'));
      // A later hold still finds the retired source in its preserved archive.
      await fixture.restartConfiguration(holdSigner!.evidence);
      const laterHold = await fixture.create(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId,
          holdKind: 'LEGAL',
          selector: { type: 'DIGEST', recordDigest: original.records[0]!.receiptDigest },
        },
      );
      expect(await custody.reconcileHolds(scope, sink)).toBeGreaterThanOrEqual(1);
      expect(await fixture.read(`evidence-holds/${laterHold.body.resourceRef}`)).toMatchObject({
        body: { coverage: 'VERIFIED' },
      });
      await fixture.create(
        `evidence-holds/${laterHold.body.resourceRef}/release`,
        'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
        { targetRef: laterHold.body.resourceRef, expectedRevision: '1' },
      );
      await custody.reconcileHolds(scope, sink);
      // Ordinary recovery may admit newly produced occurrences, never retired ones.
      // Choose a fresh supported policy receipt for the export reference denial.
      if (producer === 'retention-policy') await policy('RAW_SOURCE_BODY');
      const nextSegment = await ingest(scope, encryption, retentionUntil, 1048576);
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.evidence_catalogue where participant_id=$1 and record_id=any($2::text[])`,
            [scope.participantId, records.map((row) => row.record_id)],
          )
        ).rows[0].n,
      ).toBe(0);
      await expect(
        custody.admit(scope, original.records, encryption, retentionUntil, 1048576),
      ).rejects.toMatchObject({ code: 'CONFLICT' });
      // A real export retains its incoming source identity even after local
      // ciphertext deletion. It cannot be erased by the projection operation.
      await custody.exportNext(scope, sink);
      const nextRecord = (
        await admin.query(
          `select evidence_id::text id,sequence::text sequence from control.evidence_catalogue c where participant_id=$1 and segment_id=$2
           and ($3::text='authentication' or openpc.retention_policy_receipt_hold_metadata(c) is not null)
           order by record_id limit 1`,
          [scope.participantId, nextSegment!.segmentId, producer],
        )
      ).rows[0];
      if (producer === 'retention-policy') {
        const unsupported = (
          await admin.query(
            `select evidence_id::text id from control.evidence_catalogue c
           where participant_id=$1 and segment_id=$2 and openpc.retention_policy_receipt_hold_metadata(c) is null
           order by record_id limit 1`,
            [scope.participantId, nextSegment!.segmentId],
          )
        ).rows[0];
        expect(unsupported).toBeDefined();
        expect(await plan(urn(unsupported.id))).toMatchObject({
          body: {
            eligible: false,
            blockers: expect.arrayContaining(['UNSUPPORTED_SOURCE']),
            selection: null,
          },
        });
      }
      const exported = await fixture.attemptMutation(
        'evidence-exports/from-selection',
        'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1',
        {
          participantId,
          selection: {
            streamId: scope.streamId,
            fromSequence: nextRecord.sequence,
            throughSequence: nextRecord.sequence,
            redactionProfileId: 'pc.evidence.minimized-audit.v1',
          },
        },
      );
      expect(exported.status, JSON.stringify(exported)).toBe(202);
      const nextPayload = await fixture.read(
        `evidence-records/${urn(nextRecord.id)}/deletion-plan`,
      );
      expect(nextPayload.body.eligible).toBe(true);
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await fixture.create('evidence-deletions', 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1', {
        participantId,
        selection: nextPayload.body.selection,
        beforeDigest: nextPayload.body.beforeDigest,
      });
      expect(await plan(urn(nextRecord.id))).toMatchObject({
        body: { eligible: false, blockers: ['REFERENCES'] },
      });
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect(
        (await foreign.read(`evidence-records/${recordRef}/search-projection-deletion-plan`))
          .status,
      ).toBe(404);
      expect((await foreign.read(`evidence-deletions/${firstRef}`)).status).toBe(404);
      const direct = await runtime.connect();
      try {
        for (const statement of [
          'delete from control.evidence_catalogue where participant_id=$1',
          'delete from control.evidence_projection_retirement where participant_id=$1',
          "update control.evidence_projection_retirement set preservation_metadata='{}' where participant_id=$1",
        ]) {
          await direct.query('begin');
          try {
            await direct.query(
              `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`,
              [scope.participantId, scope.privacyDomainId, id(), action],
            );
            await expect(direct.query(statement, [scope.participantId])).rejects.toThrow();
          } finally {
            await direct.query('rollback');
          }
        }
      } finally {
        direct.release();
      }
    } finally {
      await holdActor?.close();
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
