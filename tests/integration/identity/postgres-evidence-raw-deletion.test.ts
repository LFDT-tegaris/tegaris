import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  verifyReceiptCose,
  decodeAdmittedReceipt,
} from '../../../packages/security-kernel/src/index.js';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { archiveProtectedProof } from '../../../services/control-api/src/evidence/protected-custody.js';
import { LocalProtectedProofVault } from '../../../services/control-api/src/evidence/protected-vault.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;
const policyAction = 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1';
const deletionAction = 'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1';
const time = (offset: number) =>
  new Date(Date.now() + offset).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');

// DATA MIGRATION_RETENTION_RECOVERY / SEM-052–061: independent raw policy,
// exact encrypted copy and custody; source audit/Identity records remain intact.
integration(
  'deletes raw proof copies through independent policy, real holds and a signed restart-safe keyset',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const runtime = new Pool({
      connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
      max: 1,
    });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'raw-deletion-source' };
    const rawScope = { participantId: scope.participantId, privacyDomainId: scope.privacyDomainId };
    const participantId = `urn:openpc:participant:${scope.participantId}`;
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'raw-deletion-'));
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let holdActor: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const signers: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>>[] = [];
    try {
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
        {
          protectedProofKeys: {
            activeKeyId: 'raw-delete-key',
            keys: new Map([['raw-delete-key', randomBytes(32)]]),
          },
        },
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
      const policy = {
        dataClass: 'RAW_SOURCE_BODY',
        policyVersion: '1.0.0',
        retentionPeriodMs: '0',
        localGraceMs: '0',
        sinkQuorum: 2,
        deletionMode: 'ROW_DELETE',
        makerCheckerRequired: true,
      };
      await fixture.restartConfiguration(policySigner!.evidence);
      // An independently active audit policy cannot authorize this raw copy.
      await fixture.create('retention-policies', policyAction, {
        participantId,
        predecessorPolicyId: null,
        policy: { ...policy, dataClass: 'AUDIT_EVIDENCE', sinkQuorum: 0 },
      });
      const custody = new EvidenceCustody(worker);
      await custody.ingestAuthentication(
        scope,
        { keyId: 'source-key', key: randomBytes(32) },
        time(86400000),
        1048576,
      );
      const sourceId = (
        await admin.query(
          `select c.evidence_id::text id from control.evidence_catalogue c
      join control.authentication_occurrence a on a.occurrence_id::text=c.record_id
      where c.participant_id=$1 and c.privacy_domain_id=$2 and a.method='WEBAUTHN_ASSERTION' order by c.sequence limit 1`,
          [scope.participantId, scope.privacyDomainId],
        )
      ).rows[0].id;
      const source = await fixture.read(
        `evidence-records/urn:openpc:resource:${sourceId}/protected-proof-source`,
      );
      expect(source.status, JSON.stringify(source)).toBe(200);
      const objects: string[] = [];
      const retainUntil = time(12000);
      for (let index = 0; index < 2; index++) {
        const retained = await fixture.create(
          'protected-proofs',
          'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1',
          {
            participantId,
            source: source.body,
            purpose: 'Bounded retention verification',
            caseReference: `raw-${index}`,
            retainUntil,
          },
        );
        objects.push(String(retained.body.resourceRef));
      }
      objects.sort();
      const plan = () => fixture!.read(`protected-proofs/${objects[0]}/deletion-plan`);
      expect(await plan()).toMatchObject({
        status: 200,
        body: {
          eligible: false,
          blockers: expect.arrayContaining(['NO_ACTIVE_POLICY', 'INCOMPLETE_CHECKPOINT']),
        },
      });
      const firstView = (await fixture.read(`protected-proofs/${objects[0]}`)).body;
      const binding = {
        objectRef: firstView.objectRef,
        objectVersion: firstView.objectVersion,
        objectDigest: firstView.objectDigest,
        source: firstView.source,
      };
      await fixture.create(
        'protected-proof-access',
        'ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1',
        {
          participantId,
          object: binding,
          purpose: 'Pending disclosure reference',
          caseReference: 'raw-reference',
          recipientPrincipalId: fixture.governance.maker.principalId,
          expiresAt: retainUntil,
        },
      );
      let predecessor: string | null = null,
        revision = 0;
      const activate = async (changes: Record<string, unknown> = {}) => {
        await fixture!.restartConfiguration(policySigner!.evidence);
        if (predecessor)
          await fixture!.create(
            `retention-policies/${predecessor}/retire`,
            'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1',
            { targetRef: predecessor, expectedRevision: '1' },
          );
        const created = await fixture!.create('retention-policies', policyAction, {
          participantId,
          predecessorPolicyId: predecessor,
          policy: { ...policy, policyVersion: `${++revision}.0.0`, ...changes },
        });
        predecessor = String(created.body.resourceRef);
      };
      await activate({ retentionPeriodMs: '9223372036854775807' });
      expect(await plan()).toMatchObject({
        body: {
          eligible: false,
          blockers: expect.arrayContaining(['RETENTION_NOT_ELAPSED', 'REFERENCES', 'SINK_QUORUM']),
        },
      });
      await mkdir(join(root, 'a'), { mode: 0o700 });
      await mkdir(join(root, 'b'), { mode: 0o700 });
      const sinkA = await LocalProtectedProofVault.open(join(root, 'a'), 'raw-a');
      const sinkB = await LocalProtectedProofVault.open(join(root, 'b'), 'raw-b');
      for (const object of objects)
        expect(await archiveProtectedProof(worker, rawScope, sinkA)).toMatchObject({
          objectRef: object,
        });
      expect((await plan()).body.blockers).toContain('SINK_QUORUM');
      for (const object of objects)
        expect(await archiveProtectedProof(worker, rawScope, sinkB)).toMatchObject({
          objectRef: object,
        });
      await activate({ localGraceMs: '3600000' });
      expect((await plan()).body.blockers).toContain('RETENTION_NOT_ELAPSED');
      await activate({ deletionMode: 'IDENTIFIER_ALIAS' });
      expect((await plan()).body.blockers).toContain('UNSUPPORTED_MODE');
      await activate();
      await delay(Math.max(0, Date.parse(retainUntil) - Date.now() + 25));
      const eligible = await plan();
      expect(eligible, JSON.stringify(eligible)).toMatchObject({
        status: 200,
        body: {
          eligible: true,
          blockers: [],
          selection: { dataClass: 'RAW_SOURCE_BODY', batchIndex: 0 },
        },
      });
      expect(eligible.body.selection.targets).toHaveLength(2);
      const targets = eligible.body.selection.targets;
      const snapshot = async () =>
        (
          await admin.query(
            `select
      (select count(*)::int from control.protected_proof_payload where participant_id=$1) payloads,
      (select coalesce(sum(octet_length(ciphertext)),0)::text from control.protected_proof_payload where participant_id=$1) bytes,
      (select count(*)::int from control.deletion_job where participant_id=$1) jobs,
      (select count(*)::int from control.evidence_deletion_item where participant_id=$1) items,
      (select count(*)::int from control.audit_occurrence where participant_id=$1 and aggregate_type='evidence-deletion') receipts,
      (select count(*)::int from control.outbox_event where participant_id=$1 and aggregate_type='evidence-deletion') events`,
            [scope.participantId],
          )
        ).rows[0];
      const fields = (body: Record<string, unknown>) => ({
        participantId,
        selection: body.selection,
        beforeDigest: body.beforeDigest,
      });
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const first = await fixture.prepareMutation(
        'evidence-deletions/raw-batches',
        deletionAction,
        fields(eligible.body),
        true,
      );
      expect((await first.commit()).status).toBe(403);
      holdActor = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
        { existingScope: true, businessEvidence: holdSigner!.evidence },
      );
      const holdIntent = await holdActor.prepareMutation(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
        { participantId, holdKind: 'LEGAL', selector: { type: 'PARTICIPANT' } },
      );
      await holdIntent.stepUp();
      await first.stepUp();
      const heldSnapshot = await snapshot();
      const barrier = await admin.connect();
      let held: Awaited<ReturnType<typeof holdIntent.commit>> | undefined;
      let pendingHold: ReturnType<typeof holdIntent.commit> | undefined;
      let pendingDelete: ReturnType<typeof first.commit> | undefined;
      const waitForContenders = async (count: number) => {
        let waiting = 0;
        for (let attempt = 0; attempt < 100 && waiting < count; attempt++) {
          waiting = (
            await admin.query(`select count(*)::int n from pg_stat_activity where wait_event='advisory'
            and query like '%pg_advisory_xact_lock%' and pid<>pg_backend_pid()`)
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
        pendingDelete = first.commit();
        await waitForContenders(2);
        await barrier.query('commit');
        held = await pendingHold;
        expect(held.status, JSON.stringify(held)).toBe(202);
        expect((await pendingDelete).status).toBe(412);
      } finally {
        await barrier.query('rollback');
        barrier.release();
        if (pendingHold) await pendingHold;
        if (pendingDelete) await pendingDelete;
      }
      expect((await plan()).body.blockers).toContain('ACTIVE_HOLD');
      expect(await snapshot()).toEqual(heldSnapshot);
      await fixture.restartConfiguration(holdSigner!.evidence);
      await fixture.create(
        `evidence-holds/${String(held!.body.resourceRef)}/release`,
        'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1',
        { targetRef: held!.body.resourceRef, expectedRevision: '1' },
      );
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await first.stepUp();
      const before = await snapshot();
      for (const mode of ['UNAVAILABLE', 'CORRUPT'] as const) {
        deletionSigner!.faults.mode = mode;
        expect((await first.commit()).status).toBeGreaterThanOrEqual(400);
        expect(await snapshot()).toEqual(before);
      }
      deletionSigner!.faults.mode = undefined;
      const committed = await first.commit();
      expect(committed, JSON.stringify(committed)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      const firstRef = String(committed.body.resourceRef);
      const result = await fixture.read(`evidence-deletions/${firstRef}`);
      expect(result).toMatchObject({
        status: 200,
        body: {
          deletedCount: '1',
          externalAttemptState: 'NOT_STARTED',
          selection: eligible.body.selection,
        },
      });
      expect(await snapshot()).toMatchObject({
        payloads: 1,
        jobs: 1,
        items: 1,
        receipts: 1,
        events: 1,
        bytes: String(BigInt(before.bytes) - BigInt(eligible.body.selection.ciphertextBytes)),
      });
      const receipt = (
        await admin.query(
          `select receipt_cbor,cose_sign1 from control.audit_occurrence where aggregate_id=$1 and aggregate_type='evidence-deletion'`,
          [firstRef.slice(-36)],
        )
      ).rows[0];
      expect(
        verifyReceiptCose(deletionSigner!.publicKey, receipt.receipt_cbor, receipt.cose_sign1),
      ).toBe(true);
      expect(decodeAdmittedReceipt(receipt.receipt_cbor)).toMatchObject({
        transitionProfileId: 'pc.control.evidence-deletion.raw-proof',
        operationId: committed.body.operationId,
      });
      // Lost response / process restart reconciles the original operation and cursor.
      await fixture.restartConfiguration();
      expect((await first.commit()).body).toEqual(committed.body);
      expect((await fixture.read(`evidence-deletions/${firstRef}`)).body).toEqual(result.body);
      const continuation = () =>
        fixture!.read(`evidence-deletions/${firstRef}/raw-continuation-plan`);
      const secondPlan = await continuation();
      expect(secondPlan).toMatchObject({
        status: 200,
        body: {
          eligible: true,
          selection: {
            targets,
            batchIndex: 1,
            priorCursor: { deletionJobId: firstRef, receiptDigest: result.body.receiptDigest },
          },
        },
      });
      for (const priorCursor of [
        { deletionJobId: firstRef, receiptDigest: sha256('wrong') },
        { deletionJobId: `urn:openpc:resource:${id()}`, receiptDigest: result.body.receiptDigest },
      ]) {
        const forged = await fixture.prepareMutation(
          'evidence-deletions/raw-batches',
          deletionAction,
          { ...fields(secondPlan.body), selection: { ...secondPlan.body.selection, priorCursor } },
          true,
        );
        await forged.stepUp();
        expect((await forged.commit()).status).toBeGreaterThanOrEqual(400);
      }
      const second = await fixture.prepareMutation(
        'evidence-deletions/raw-batches',
        deletionAction,
        fields(secondPlan.body),
        true,
      );
      await second.stepUp();
      await fixture.restartConfiguration(holdSigner!.evidence);
      const digestHold = await fixture.create(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId,
          holdKind: 'INCIDENT',
          selector: { type: 'DIGEST', recordDigest: secondPlan.body.selection.payloadDigest },
        },
      );
      expect((await continuation()).body).toMatchObject({
        eligible: false,
        blockers: ['ACTIVE_HOLD'],
        continuationState: 'BLOCKED',
      });
      await fixture.restartConfiguration(deletionSigner!.evidence);
      expect((await second.commit()).status).toBe(412);
      expect(await snapshot()).toMatchObject({ payloads: 1, jobs: 1 });
      await fixture.restartConfiguration(holdSigner!.evidence);
      await fixture.create(
        `evidence-holds/${String(digestHold.body.resourceRef)}/release`,
        'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
        { targetRef: digestHold.body.resourceRef, expectedRevision: '1' },
      );
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await second.stepUp();
      const secondResult = await second.commit();
      expect(secondResult, JSON.stringify(secondResult)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      const secondRef = String(secondResult.body.resourceRef);
      expect(
        (await fixture.read(`evidence-deletions/${secondRef}/raw-continuation-plan`)).body
          .continuationState,
      ).toBe('COMPLETE');
      expect((await continuation()).body).toMatchObject({
        continuationState: 'ADVANCED',
        nextDeletionJobId: secondRef,
      });
      await fixture.restartConfiguration();
      expect((await second.commit()).body).toEqual(secondResult.body);
      expect(await snapshot()).toMatchObject({
        payloads: 0,
        bytes: '0',
        jobs: 2,
        items: 2,
        receipts: 2,
        events: 2,
      });
      expect((await plan()).body).toMatchObject({
        localPayload: 'DELETED',
        blockers: ['ALREADY_DELETED'],
      });
      expect((await fixture.read(`protected-proofs/${objects[0]}`)).body).toEqual(firstView);
      expect(
        (
          await fixture.read(
            `evidence-records/urn:openpc:resource:${sourceId}/protected-proof-source`,
          )
        ).body,
      ).toEqual(source.body);
      for (const row of (
        await admin.query(
          'select receipt from control.protected_proof_checkpoint where participant_id=$1',
          [scope.participantId],
        )
      ).rows)
        expect(
          await (row.receipt.object.sinkId === 'raw-a' ? sinkA : sinkB).verify(row.receipt.object),
        ).toEqual(row.receipt);
      expect(await archiveProtectedProof(worker, rawScope, sinkA)).toBeNull();
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect((await foreign.read(`protected-proofs/${objects[0]}/deletion-plan`)).status).toBe(404);
      expect((await foreign.read(`evidence-deletions/${firstRef}`)).status).toBe(404);
      expect((await fixture.read(`evidence-deletions/${firstRef}`, { Cookie: '' })).status).toBe(
        401,
      );
      const direct = await runtime.connect();
      try {
        await direct.query('begin');
        await direct.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
          scope.participantId,
          scope.privacyDomainId,
          id(),
          deletionAction,
        ]);
        await expect(
          direct.query(
            `update control.deletion_job set state='EXECUTING',revision=0 where participant_id=$1`,
            [scope.participantId],
          ),
        ).rejects.toThrow();
      } finally {
        await direct.query('rollback');
        direct.release();
      }
    } finally {
      await foreign?.close();
      await holdActor?.close();
      await fixture?.close();
      for (const signer of signers) await signer.close();
      await runtime.end();
      await worker.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  120000,
);
