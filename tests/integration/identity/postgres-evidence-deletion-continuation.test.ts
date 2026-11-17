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
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;
const action = 'ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1';

// TP-RETENTION-RECOVERY / SEM-059: public catalogue selection, independent
// approvals and live gates; immutable signed cursor across actual local effects.
integration(
  'continues an ordered signed deletion keyset without skipping, duplicating or resubmitting effects',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'deletion-continuation' };
    const participantId = `urn:openpc:participant:${scope.participantId}`;
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'deletion-continuation-'));
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let rival: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let limited: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
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
      const custody = new EvidenceCustody(worker);
      const encryption = { keyId: 'continuation-test-key', key: randomBytes(32) };
      const past = new Date(Date.now() - 1000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
      const objects: NonNullable<Awaited<ReturnType<typeof custody.ingestAuthentication>>>[] = [];
      for (const dataClass of ['RAW_SOURCE_BODY', 'AUDIT_EVIDENCE']) {
        await fixture.restartConfiguration(policySigner!.evidence);
        await fixture.create('retention-policies', 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1', {
          participantId,
          predecessorPolicyId: null,
          policy: {
            dataClass,
            policyVersion: '1.0.0',
            retentionPeriodMs: '0',
            localGraceMs: '0',
            sinkQuorum: 1,
            deletionMode: 'ROW_DELETE',
            makerCheckerRequired: true,
          },
        });
        const object = await custody.ingestAuthentication(scope, encryption, past, 1048576);
        expect(object).not.toBeNull();
        objects.push(object!);
      }
      await fixture.restartConfiguration(holdSigner!.evidence);
      const createHold = (fromSequence = '1', throughSequence: string | null = null) =>
        fixture!.create('evidence-holds', 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1', {
          participantId,
          holdKind: 'LEGAL',
          selector: {
            type: 'SEQUENCE_RANGE',
            streamId: scope.streamId,
            fromSequence,
            throughSequence,
          },
        });
      const releaseHold = (reference: string) =>
        fixture!.create(
          `evidence-holds/${reference}/release`,
          'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
          { targetRef: reference, expectedRevision: '1' },
        );
      const seedHold = await createHold();
      await releaseHold(String(seedHold.body.resourceRef));
      const third = await custody.ingestAuthentication(scope, encryption, past, 1048576);
      expect(third).not.toBeNull();
      objects.push(third!);
      const records = (await fixture.read('evidence-records')).body.items as {
        evidenceId: string;
        sequence: string;
      }[];
      const firstSegment = objects.map((object) => object.segmentId).sort()[0]!;
      // Public catalogue references are the only selection inputs. SQL below is
      // read-only effect/receipt verification, not intermediate business setup.
      const firstRecord = records.find(
        (record) =>
          record.sequence ===
          objects.find((object) => object.segmentId === firstSegment)!.firstSequence,
      );
      expect(firstRecord).toBeDefined();
      const initial = () =>
        fixture!.read(`evidence-records/${firstRecord!.evidenceId}/deletion-batch-plan`);
      expect(await initial()).toMatchObject({
        status: 200,
        body: { eligible: false, blockers: expect.arrayContaining(['INCOMPLETE_CHECKPOINT']) },
      });
      const sink = await LocalEvidenceVault.open(join(root, 'archive'), 'continuation-archive');
      for (let index = 0; index < objects.length; index++)
        expect(await custody.exportNext(scope, sink)).not.toBeNull();
      const selected = await initial();
      expect(selected).toMatchObject({
        status: 200,
        body: {
          eligible: true,
          continuationState: 'READY',
          selection: { batchIndex: 0, priorCursor: null },
        },
      });
      expect(selected.body.selection.targets).toHaveLength(3);
      const targets = selected.body.selection.targets;
      expect(targets.map((target: { segmentId: string }) => target.segmentId)).toEqual(
        objects.map((object) => object.segmentId).sort(),
      );
      const retained = (
        await admin.query(
          `select s.segment_id::text,s.object_digest,p.encrypted_segment,c.receipt
      from control.evidence_segment s join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id)
      join control.evidence_checkpoint c using(participant_id,privacy_domain_id,stream_id,segment_id)
      where s.participant_id=$1 order by s.segment_id`,
          [scope.participantId],
        )
      ).rows;
      const originalSources = (
        await admin.query(
          `select a.occurrence_id::text,a.receipt from control.authentication_occurrence a
        join control.evidence_catalogue c on c.record_id=a.occurrence_id::text and c.participant_id=a.participant_id
        where c.participant_id=$1 and c.stream_id=$2 order by a.occurrence_id`,
          [scope.participantId, scope.streamId],
        )
      ).rows;
      expect(originalSources.length).toBeGreaterThanOrEqual(6);
      const snapshot = async () =>
        (
          await admin.query(
            `select
      (select count(*)::int from control.deletion_job where participant_id=$1) jobs,
      (select count(*)::int from control.evidence_deletion_item where participant_id=$1) items,
      (select count(*)::int from control.evidence_segment_payload where participant_id=$1) payloads,
      (select count(*)::int from control.audit_occurrence where participant_id=$1 and aggregate_type='evidence-deletion') receipts,
      (select count(*)::int from control.outbox_event where participant_id=$1 and aggregate_type='evidence-deletion') events,
      (select count(*)::int from control.receipt_signing_attempt a join control.business_transition_profile p using(profile_digest) where a.participant_id=$1 and p.profile_id='pc.control.evidence-deletion.batch') attempts,
      (select used_bytes::int from control.evidence_stream where participant_id=$1 and stream_id=$2) bytes`,
            [scope.participantId, scope.streamId],
          )
        ).rows[0];
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const fields = (plan: typeof selected) => ({
        participantId,
        selection: plan.body.selection,
        beforeDigest: plan.body.beforeDigest,
      });
      limited = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
        { existingScope: true, resourceIds: [firstRecord!.evidenceId.slice(-36)] },
      );
      expect(
        (await limited.read(`evidence-records/${firstRecord!.evidenceId}/deletion-plan`)).status,
      ).toBe(200);
      expect(
        (await limited.read(`evidence-records/${firstRecord!.evidenceId}/deletion-batch-plan`))
          .status,
      ).toBe(403);
      const first = await fixture.prepareMutation(
        'evidence-deletions/batches',
        action,
        fields(selected),
        true,
      );
      expect((await first.commit()).status).toBe(403);
      await first.stepUp();
      const before = await snapshot();
      const committed = await first.commit();
      expect(committed).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
      const firstRef = String(committed.body.resourceRef);
      const firstResult = await fixture.read(`evidence-deletions/${firstRef}`);
      const continuation = (reference: string) =>
        fixture!.read(`evidence-deletions/${reference}/continuation-plan`);
      const secondPlan = await continuation(firstRef);
      expect(secondPlan).toMatchObject({
        status: 200,
        body: {
          eligible: true,
          selection: {
            targets,
            batchIndex: 1,
            priorCursor: { deletionJobId: firstRef, receiptDigest: firstResult.body.receiptDigest },
          },
        },
      });
      const second = await fixture.prepareMutation(
        'evidence-deletions/batches',
        action,
        fields(secondPlan),
        true,
      );
      await second.stepUp();
      await fixture.restartConfiguration(holdSigner!.evidence);
      const hold = await createHold(
        secondPlan.body.selection.firstSequence,
        secondPlan.body.selection.throughSequence,
      );
      expect((await continuation(firstRef)).body).toMatchObject({
        eligible: false,
        continuationState: 'BLOCKED',
        blockers: ['ACTIVE_HOLD'],
      });
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const blocked = await snapshot();
      expect((await second.commit()).status).toBe(412);
      expect(await snapshot()).toEqual(blocked);
      await fixture.restartConfiguration(holdSigner!.evidence);
      await releaseHold(String(hold.body.resourceRef));
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await second.stepUp();
      const rollback = await snapshot();
      for (const mode of ['UNAVAILABLE', 'CORRUPT'] as const) {
        deletionSigner!.faults.mode = mode;
        expect((await second.commit()).status).toBeGreaterThanOrEqual(400);
        expect(await snapshot()).toEqual(rollback);
      }
      deletionSigner!.faults.mode = undefined;
      // The predecessor and the remaining targets are signed, not assertions
      // that a newly approved caller may replace.
      for (const change of [
        {
          priorCursor: {
            ...secondPlan.body.selection.priorCursor,
            receiptDigest: `sha256:${'fe'.repeat(32)}`,
          },
        },
        {
          priorCursor: {
            ...secondPlan.body.selection.priorCursor,
            deletionJobId: `urn:openpc:resource:${id()}`,
          },
        },
        {
          targets: targets.map((target: { objectDigest: string }, index: number) =>
            index === 2 ? { ...target, objectDigest: `sha256:${'ef'.repeat(32)}` } : target,
          ),
        },
      ]) {
        const forged = await fixture.prepareMutation(
          'evidence-deletions/batches',
          action,
          { ...fields(secondPlan), selection: { ...secondPlan.body.selection, ...change } },
          true,
        );
        await forged.stepUp();
        expect((await forged.commit()).status).toBe(412);
        expect(await snapshot()).toEqual(rollback);
      }
      // Real PostgreSQL failure after DELETE and accounting must roll the entire
      // signed transaction back. This fault does not replace any internal owner.
      await admin.query(`create function public.fail_deletion_storage_test() returns trigger language plpgsql as $$
        begin if NEW.aggregate_type='evidence-deletion' then raise exception 'test storage failure'; end if; return NEW; end $$;
        create trigger fail_deletion_storage_test before insert on control.outbox_event for each row execute function public.fail_deletion_storage_test()`);
      try {
        await second.stepUp();
        expect((await second.commit()).status).toBeGreaterThanOrEqual(400);
        expect(await snapshot()).toEqual(rollback);
      } finally {
        await admin.query(
          'drop trigger fail_deletion_storage_test on control.outbox_event; drop function public.fail_deletion_storage_test()',
        );
      }
      const secondCommitted = await second.commit();
      expect(secondCommitted).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
      const secondRef = String(secondCommitted.body.resourceRef);
      expect((await continuation(firstRef)).body).toMatchObject({
        continuationState: 'ADVANCED',
        eligible: false,
        nextDeletionJobId: secondRef,
      });
      const afterSecond = await snapshot();
      // Simulate losing the response at the caller: restart and use original
      // durable operation/result readback, without another business submission.
      await fixture.restartConfiguration();
      expect(
        (await fixture.read(`operations/${secondCommitted.body.operationId}`)).body,
      ).toMatchObject({ state: 'SUCCEEDED' });
      expect((await fixture.read(`evidence-deletions/${secondRef}`)).body.selection).toEqual(
        secondPlan.body.selection,
      );
      expect(await snapshot()).toEqual(afterSecond);
      expect((await first.commit()).body).toEqual(committed.body);
      expect((await second.commit()).body).toEqual(secondCommitted.body);
      const thirdPlan = await continuation(secondRef);
      expect(thirdPlan.body).toMatchObject({
        eligible: true,
        selection: { targets, batchIndex: 2 },
      });
      const thirdPrepared = await fixture.prepareMutation(
        'evidence-deletions/batches',
        action,
        fields(thirdPlan),
        true,
      );
      await thirdPrepared.stepUp();
      rival = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
        { existingScope: true, businessEvidence: deletionSigner!.evidence },
      );
      const contender = await rival.prepareMutation(
        'evidence-deletions/batches',
        action,
        fields(thirdPlan),
        true,
      );
      await contender.stepUp();
      const barrier = await admin.connect();
      let pending: Promise<Awaited<ReturnType<typeof thirdPrepared.commit>>[]> | undefined;
      let results: Awaited<ReturnType<typeof thirdPrepared.commit>>[] = [];
      try {
        await barrier.query('begin');
        await barrier.query(
          `select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0)), $2::uuid`,
          [scope.participantId, scope.privacyDomainId],
        );
        pending = Promise.all([thirdPrepared.commit(), contender.commit()]);
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
        results = await pending;
        expect(results.map((result) => result.status).sort()).toEqual([202, 412]);
      } finally {
        await barrier.query('rollback');
        barrier.release();
        if (pending) await pending;
      }
      const final = results.find((result) => result.status === 202)!;
      expect(final).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
      expect((await continuation(String(final.body.resourceRef))).body).toMatchObject({
        continuationState: 'COMPLETE',
        eligible: false,
        selection: null,
        nextDeletionJobId: null,
      });
      expect(await snapshot()).toEqual({
        ...before,
        jobs: 3,
        items: 3,
        payloads: 0,
        receipts: before.receipts + 3,
        attempts: before.attempts + 3,
        events: before.events + 3,
        bytes: 0,
      });
      for (const row of retained) {
        expect(await sink.read(row.receipt.object)).toEqual(row.encrypted_segment);
        expect(
          (
            await admin.query(
              'select object_digest from control.evidence_segment where participant_id=$1 and segment_id=$2',
              [scope.participantId, row.segment_id],
            )
          ).rows[0].object_digest,
        ).toBe(row.object_digest);
      }
      const receipts = (
        await admin.query(
          `select receipt_cbor,cose_sign1 from control.audit_occurrence where participant_id=$1 and aggregate_type='evidence-deletion'`,
          [scope.participantId],
        )
      ).rows;
      expect(receipts).toHaveLength(3);
      for (const receipt of receipts) {
        expect(
          verifyReceiptCose(deletionSigner!.publicKey, receipt.receipt_cbor, receipt.cose_sign1),
        ).toBe(true);
        expect(decodeAdmittedReceipt(receipt.receipt_cbor)).toMatchObject({
          transitionProfileId: 'pc.control.evidence-deletion.batch',
        });
      }
      for (const source of originalSources)
        expect(
          (
            await admin.query(
              'select receipt from control.authentication_occurrence where participant_id=$1 and occurrence_id=$2',
              [scope.participantId, source.occurrence_id],
            )
          ).rows[0].receipt,
        ).toEqual(source.receipt);
      // An independent stream tests a policy generation change after partial
      // progress. No earlier candidate or completed effect is reused.
      const policyScope = { ...scope, streamId: 'deletion-policy-cutover' };
      const policyObjectA = await custody.ingestAuthentication(
        policyScope,
        encryption,
        past,
        1048576,
      );
      expect(policyObjectA).not.toBeNull();
      await fixture.restartConfiguration(holdSigner!.evidence);
      const policyHold = await fixture.create(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId,
          holdKind: 'INCIDENT',
          selector: {
            type: 'SEQUENCE_RANGE',
            streamId: policyScope.streamId,
            fromSequence: '1',
            throughSequence: null,
          },
        },
      );
      await releaseHold(String(policyHold.body.resourceRef));
      const policyObjectB = await custody.ingestAuthentication(
        policyScope,
        encryption,
        past,
        1048576,
      );
      expect(policyObjectB).not.toBeNull();
      await custody.exportNext(policyScope, sink);
      await custody.exportNext(policyScope, sink);
      // Resolve the independent stream through the public export-range owner,
      // since the catalogue deliberately does not expose its internal stream ID.
      const allRecords = (await fixture.read('evidence-records?limit=200')).body.items;
      const firstPolicyObject = [policyObjectA!, policyObjectB!].sort((a, b) =>
        a.segmentId.localeCompare(b.segmentId),
      )[0]!;
      let policyRecord: string | undefined;
      for (const record of allRecords as { evidenceId: string; sequence: string }[]) {
        if (record.sequence !== firstPolicyObject.firstSequence) continue;
        const range = await fixture.read(`evidence-records/${record.evidenceId}/export-range`);
        if (range.body.range.streamId === policyScope.streamId) policyRecord = record.evidenceId;
      }
      expect(policyRecord).toBeDefined();
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const policyPlan = await fixture.read(`evidence-records/${policyRecord}/deletion-batch-plan`);
      expect(policyPlan.body).toMatchObject({ eligible: true });
      expect(policyPlan.body.selection.targets).toHaveLength(2);
      const policyFirst = await fixture.create(
        'evidence-deletions/batches',
        action,
        fields(policyPlan),
      );
      const policyNext = await continuation(String(policyFirst.body.resourceRef));
      const stalePolicy = await fixture.prepareMutation(
        'evidence-deletions/batches',
        action,
        fields(policyNext),
        true,
      );
      await stalePolicy.stepUp();
      const originalPolicy = policyNext.body.selection.retentionPolicyId;
      await fixture.restartConfiguration(policySigner!.evidence);
      await fixture.create(
        `retention-policies/${originalPolicy}/retire`,
        'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1',
        { targetRef: originalPolicy, expectedRevision: '1' },
      );
      expect((await continuation(String(policyFirst.body.resourceRef))).body).toMatchObject({
        eligible: false,
        continuationState: 'BLOCKED',
        blockers: expect.arrayContaining(['NO_ACTIVE_POLICY']),
      });
      await fixture.create('retention-policies', 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1', {
        participantId,
        predecessorPolicyId: originalPolicy,
        policy: {
          dataClass: 'AUDIT_EVIDENCE',
          policyVersion: '2.0.0',
          retentionPeriodMs: '0',
          localGraceMs: '0',
          sinkQuorum: 1,
          deletionMode: 'ROW_DELETE',
          makerCheckerRequired: true,
        },
      });
      expect((await continuation(String(policyFirst.body.resourceRef))).body).toMatchObject({
        eligible: false,
        continuationState: 'BLOCKED',
        blockers: ['STALE_SELECTION'],
        selection: null,
      });
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const cutover = await snapshot();
      await stalePolicy.stepUp();
      expect((await stalePolicy.commit()).status).toBe(412);
      expect(await snapshot()).toEqual(cutover);
      expect((await continuation(String(final.body.resourceRef))).body.continuationState).toBe(
        'COMPLETE',
      );
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect((await foreign.read(`evidence-deletions/${firstRef}/continuation-plan`)).status).toBe(
        404,
      );
      expect(
        (await foreign.read(`evidence-records/${firstRecord!.evidenceId}/deletion-batch-plan`))
          .status,
      ).toBe(404);
    } finally {
      for (const signer of signers) signer.close();
      await limited?.close();
      await rival?.close();
      await foreign?.close();
      await fixture?.close();
      await worker.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  120000,
);
