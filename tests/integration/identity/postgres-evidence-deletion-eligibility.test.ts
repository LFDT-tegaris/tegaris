import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;
const deletionAction = 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1';

// Independent policy/gate scenarios do not reuse the main deletion's objects,
// approval candidates, idempotency keys, authenticator counters or fault controls.
integration(
  'rechecks exact policy versions, time, quorum and storage promises and refuses an unsigned local deletion effect',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const runtime = new Pool({
      connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
      max: 1,
    });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'deletion-eligibility' };
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'deletion-eligibility-'));
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const signers: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>>[] = [];
    try {
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
      );
      for (const family of ['retention-policy', 'evidence-deletion'] as const)
        signers.push(
          await evidenceGovernanceSigningFixture(
            admin,
            scope.participantId,
            scope.privacyDomainId,
            family,
          ),
        );
      const [policySigner, deletionSigner] = signers;
      const participantId = `urn:openpc:participant:${scope.participantId}`;
      let predecessor: string | null = null,
        version = 0;
      const policy = {
        dataClass: 'AUDIT_EVIDENCE',
        retentionPeriodMs: '0',
        localGraceMs: '0',
        sinkQuorum: 2,
        deletionMode: 'ROW_DELETE',
        makerCheckerRequired: true,
      };
      const activate = async (change: Record<string, unknown> = {}) => {
        await fixture!.restartConfiguration(policySigner!.evidence);
        const result = await fixture!.create(
          'retention-policies',
          'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',
          {
            participantId,
            predecessorPolicyId: predecessor,
            policy: { ...policy, policyVersion: `${++version}.0.0`, ...change },
          },
        );
        predecessor = String(result.body.resourceRef);
        return predecessor;
      };
      const retire = async () => {
        await fixture!.restartConfiguration(policySigner!.evidence);
        await fixture!.create(
          `retention-policies/${predecessor}/retire`,
          'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1',
          {
            targetRef: predecessor,
            expectedRevision: '1',
          },
        );
      };
      // Public policy governance creates the real WebAuthn source receipts used below.
      await activate({
        retentionPeriodMs: '9223372036854775807',
        localGraceMs: '9223372036854775807',
      });
      const custody = new EvidenceCustody(worker),
        encryption = { keyId: 'eligibility-key', key: randomBytes(32) };
      const past = new Date(Date.now() - 1000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
      const first = await custody.ingestAuthentication(scope, encryption, past, 1048576);
      expect(first).not.toBeNull();
      const record = (
        await admin.query(
          `select evidence_id::text id from control.evidence_catalogue where participant_id=$1 and segment_id=$2 order by sequence limit 1`,
          [scope.participantId, first!.segmentId],
        )
      ).rows[0].id;
      const plan = () =>
        fixture!.read(`evidence-records/urn:openpc:resource:${record}/deletion-plan`);
      const sinkA = await LocalEvidenceVault.open(join(root, 'a'), 'archive-a');
      const sinkB = await LocalEvidenceVault.open(join(root, 'b'), 'archive-b');
      expect(await plan()).toMatchObject({
        body: {
          eligible: false,
          blockers: expect.arrayContaining([
            'INCOMPLETE_CHECKPOINT',
            'RETENTION_NOT_ELAPSED',
            'SINK_QUORUM',
          ]),
        },
      });
      await custody.exportNext(scope, sinkA);
      expect(await plan()).toMatchObject({
        body: { eligible: false, blockers: ['SINK_QUORUM', 'RETENTION_NOT_ELAPSED'] },
      });
      await custody.exportNext(scope, sinkB);
      const enormous = await plan();
      expect(enormous).toMatchObject({
        body: { eligible: false, blockers: ['RETENTION_NOT_ELAPSED'] },
      });
      expect(BigInt(enormous.body.selection.eligibleAfterMicros)).toBeGreaterThan(
        9223372036854775807n * 1000n,
      );
      // Period and grace are independent gates; no unsafe integer conversion or
      // silently shortened protection is permitted even for an otherwise ready sink.
      await retire();
      await activate({ retentionPeriodMs: '0', localGraceMs: '3600000' });
      expect(await plan()).toMatchObject({
        body: { eligible: false, blockers: ['RETENTION_NOT_ELAPSED'] },
      });
      await retire();
      await activate({ deletionMode: 'IDENTIFIER_ALIAS' });
      expect(await plan()).toMatchObject({
        body: { eligible: false, blockers: ['UNSUPPORTED_MODE'] },
      });
      await retire();
      await activate();
      const ready = await plan();
      expect(ready).toMatchObject({ status: 200, body: { eligible: true, blockers: [] } });
      // Direct SQL can neither manufacture the actual-delete attestation nor commit
      // an actual local effect without consumed approval and a signed receipt.
      const direct = await runtime.connect();
      const job = id(),
        operation = id();
      try {
        await direct.query('begin');
        await direct.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
          scope.participantId,
          scope.privacyDomainId,
          operation,
          deletionAction,
        ]);
        await direct.query(
          `insert into control.deletion_job(deletion_job_id,participant_id,privacy_domain_id,retention_policy_id,stream_id,segment_id,selection,before_digest,approval_request_id,operation_id,attempt_id)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [
            job,
            scope.participantId,
            scope.privacyDomainId,
            String(predecessor).slice(-36),
            scope.streamId,
            first!.segmentId,
            ready.body.selection,
            ready.body.beforeDigest,
            id(),
            operation,
            id(),
          ],
        );
        await direct.query('savepoint fabricated_effect');
        await expect(
          direct.query(
            `insert into control.evidence_deletion_item(participant_id,privacy_domain_id,deletion_job_id,segment_id,object_digest,ciphertext_bytes)
    values($1,$2,$3,$4,$5,$6)`,
            [
              scope.participantId,
              scope.privacyDomainId,
              job,
              first!.segmentId,
              first!.objectDigest,
              ready.body.selection.ciphertextBytes,
            ],
          ),
        ).rejects.toThrow('PC-AUTH-0005');
        await direct.query('rollback to savepoint fabricated_effect');
        expect(
          (
            await direct.query(
              'delete from control.evidence_segment_payload where participant_id=$1 and segment_id=$2',
              [scope.participantId, first!.segmentId],
            )
          ).rowCount,
        ).toBe(1);
        await direct.query(
          `update control.evidence_stream set used_bytes=used_bytes-$3 where participant_id=$1 and stream_id=$2`,
          [scope.participantId, scope.streamId, ready.body.selection.ciphertextBytes],
        );
        await direct.query(
          `update control.deletion_job set state='SUCCEEDED',revision=1 where deletion_job_id=$1`,
          [job],
        );
        await expect(direct.query('commit')).rejects.toThrow('PC-AUTH-0002-DELETION-SIGNED-EFFECT');
      } finally {
        await direct.query('rollback');
        direct.release();
      }
      expect(await plan()).toMatchObject({ body: { eligible: true, localPayload: 'RETAINED' } });
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.deletion_job where participant_id=$1',
            [scope.participantId],
          )
        ).rows[0].n,
      ).toBe(0);
      await fixture.restartConfiguration(deletionSigner!.evidence);
      const stale = await fixture.prepareMutation(
        'evidence-deletions',
        deletionAction,
        { participantId, selection: ready.body.selection, beforeDigest: ready.body.beforeDigest },
        true,
      );
      await retire();
      expect(await plan()).toMatchObject({
        body: { eligible: false, blockers: ['NO_ACTIVE_POLICY'] },
      });
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await stale.stepUp();
      expect((await stale.commit()).status).toBe(412);
      await activate();
      expect((await plan()).body.selection.retentionPolicyId).not.toBe(
        ready.body.selection.retentionPolicyId,
      );
      await fixture.restartConfiguration(deletionSigner!.evidence);
      await stale.stepUp();
      expect((await stale.commit()).status).toBe(412);
      // Original storage promises remain independent of a later zero-period policy.
      const protectedScope = { ...scope, streamId: 'protected-until-future' };
      const future = new Date(Date.now() + 3600000)
        .toISOString()
        .replace(/\.(\d{3})Z$/u, '.$1000Z');
      const protectedObject = await custody.ingestAuthentication(
        protectedScope,
        encryption,
        future,
        1048576,
      );
      expect(protectedObject).not.toBeNull();
      await custody.exportNext(protectedScope, sinkA);
      await custody.exportNext(protectedScope, sinkB);
      const protectedId = (
        await admin.query(
          'select evidence_id::text id from control.evidence_catalogue where participant_id=$1 and segment_id=$2 order by sequence limit 1',
          [scope.participantId, protectedObject!.segmentId],
        )
      ).rows[0].id;
      expect(
        await fixture.read(`evidence-records/urn:openpc:resource:${protectedId}/deletion-plan`),
      ).toMatchObject({ body: { eligible: false, blockers: ['RETENTION_NOT_ELAPSED'] } });
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.evidence_segment_payload where participant_id=$1',
            [scope.participantId],
          )
        ).rows[0].n,
      ).toBe(2);
    } finally {
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
