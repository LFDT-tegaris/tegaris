import { randomBytes } from 'node:crypto';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import { type SourceReceipt } from '../../../services/control-api/src/evidence/segment.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;

// SEM-053/054/055/056/057/058: custody owner segment only. These fixture bytes
// do not establish receipt authentication, the public governance journey, or
// production storage assurance. The sink, PostgreSQL and their effects are real.
integration(
  'commits sink-bound contiguous evidence checkpoints only after durable exact acknowledgement',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'evidence-'));
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'control-receipts' };
    const retentionUntil = '2027-01-01T00:00:00.000000Z';
    const encryption = { keyId: 'local-test-key', key: randomBytes(32) };
    const batch = (): SourceReceipt[] =>
      ['AUTHENTICATION', 'BUSINESS_TRANSITION', 'EFFECT'].map((kind) => {
        const bytes = Buffer.from(`source fixture ${id()}`);
        return {
          recordId: id(),
          evidenceClass: kind as SourceReceipt['evidenceClass'],
          sourceFormat: 'FIXTURE',
          occurredAt: '2026-09-21T00:00:00.000000Z',
          receiptDigest: sha256(bytes),
          receiptBase64: bytes.toString('base64'),
        };
      });
    const count = async (table: string) =>
      (
        await admin.query<{ count: number }>(
          `select count(*)::int as count from control.${table} where participant_id=$1`,
          [scope.participantId],
        )
      ).rows[0]!.count;
    try {
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Evidence initial trust','ACTIVE',1)`,
        [scope.participantId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
      values($1,$2,'Evidence','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [scope.privacyDomainId, scope.participantId],
      );
      await admin.query(
        `update control.participant set root_privacy_domain_id=$2 where participant_id=$1`,
        [scope.participantId, scope.privacyDomainId],
      );
      const custody = new EvidenceCustody(worker);
      const first = batch();
      const admitted = await custody.admit(scope, first, encryption, retentionUntil, 65536);
      expect(admitted).toMatchObject({
        firstSequence: '1',
        throughSequence: '3',
        custody: 'CONTROL_POSTGRES',
        sinkQuorum: 0,
      });
      expect(await custody.admit(scope, first, encryption, retentionUntil, 65536)).toEqual(
        admitted,
      );
      expect(await count('evidence_segment')).toBe(1);
      expect(await count('evidence_segment_payload')).toBe(1);
      expect(await count('evidence_checkpoint')).toBe(0);
      const conflicting = batch();
      conflicting[0] = { ...conflicting[0]!, recordId: first[0]!.recordId };
      await expect(
        custody.admit(scope, conflicting, encryption, retentionUntil, 65536),
      ).rejects.toThrow('conflict');
      await expect(
        custody.admit({ ...scope, streamId: 'capacity' }, first, encryption, retentionUntil, 1024),
      ).rejects.toThrow('capacity');
      expect(await count('evidence_stream')).toBe(1);
      expect(await count('evidence_catalogue')).toBe(3);

      const unavailable = await LocalEvidenceVault.open(join(root, 'unavailable'), 'local-sink');
      await rm(join(root, 'unavailable'), { recursive: true });
      await expect(custody.exportNext(scope, unavailable)).rejects.toThrow('unavailable');
      expect(await count('evidence_checkpoint')).toBe(0);
      const vault = await LocalEvidenceVault.open(join(root, 'vault'), 'local-sink');

      // Real sink persistence followed by failed database commit: a retry must
      // recover the exact object rather than re-encrypt, skip or duplicate it.
      await admin.query(`create function openpc.test_evidence_checkpoint_failure() returns trigger language plpgsql as $$ begin raise exception 'TEST_CHECKPOINT_COMMIT_FAILURE'; end $$;
      create trigger test_evidence_checkpoint_failure before insert on control.evidence_checkpoint for each row execute function openpc.test_evidence_checkpoint_failure()`);
      await expect(custody.exportNext(scope, vault)).rejects.toThrow(
        'TEST_CHECKPOINT_COMMIT_FAILURE',
      );
      expect(await count('evidence_checkpoint')).toBe(0);
      expect(
        (await readdir(join(root, 'vault'))).filter((name) => name.endsWith('.segment')),
      ).toHaveLength(1);
      await admin.query(
        'drop trigger test_evidence_checkpoint_failure on control.evidence_checkpoint; drop function openpc.test_evidence_checkpoint_failure()',
      );
      const recovered = await new EvidenceCustody(worker).exportNext(
        scope,
        await LocalEvidenceVault.open(join(root, 'vault'), 'local-sink'),
      );
      expect(recovered).toMatchObject({
        throughSequence: '3',
        previousCheckpointDigest: null,
        objectDigest: admitted.objectDigest,
        assurance: 'LOCAL_FSYNC_READBACK',
      });
      expect(await count('evidence_checkpoint')).toBe(1);
      expect(await custody.exportNext(scope, vault)).toBeNull();
      expect(
        (await readdir(join(root, 'vault'))).filter((name) => name.endsWith('.segment')),
      ).toHaveLength(1);

      await custody.admit(scope, batch(), encryption, retentionUntil, 65536);
      const competing = await Promise.all([
        custody.exportNext(scope, vault),
        custody.exportNext(scope, vault),
      ]);
      expect(competing.filter(Boolean)).toHaveLength(1);
      expect(competing.find(Boolean)).toMatchObject({
        throughSequence: '6',
        previousCheckpointDigest: recovered!.checkpointDigest,
      });
      expect(await count('evidence_checkpoint')).toBe(2);
      // Each distinct sink starts at sequence 1; one sink's progress grants no
      // custody claim for another sink, including an identical storage directory.
      const second = await LocalEvidenceVault.open(join(root, 'other-vault'), 'other-sink');
      expect(await custody.exportNext(scope, second)).toMatchObject({
        throughSequence: '3',
        previousCheckpointDigest: null,
        sinkId: 'other-sink',
      });

      const client = await worker.connect();
      try {
        await client.query('begin');
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, id(), id()],
        );
        expect((await client.query('select * from control.evidence_catalogue')).rowCount).toBe(0);
        expect((await client.query('select * from control.evidence_checkpoint')).rowCount).toBe(0);
        expect(
          (await client.query('select * from control.evidence_segment_payload')).rowCount,
        ).toBe(0);
        await client.query('rollback');
        // Metadata cannot commit unless its exact ciphertext is admitted too.
        await client.query('begin');
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, scope.privacyDomainId, id()],
        );
        await client.query(
          `insert into control.evidence_segment(participant_id,privacy_domain_id,stream_id,segment_id,
           first_sequence,through_sequence,previous_segment_digest,object_digest,key_id,retention_until)
           select s.participant_id,s.privacy_domain_id,s.stream_id,$4,h.last_sequence+1,h.last_sequence+1,
           h.last_segment_digest,s.object_digest,s.key_id,s.retention_until
           from control.evidence_segment s join control.evidence_stream h using(participant_id,privacy_domain_id,stream_id)
           where s.participant_id=$1 and s.privacy_domain_id=$2 and s.stream_id=$3 and s.through_sequence=h.last_sequence`,
          [...Object.values(scope), id()],
        );
        await expect(client.query('commit')).rejects.toThrow('PC-DATA-6004-EVIDENCE-PAYLOAD');
        await client.query('rollback');
        await client.query('begin');
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, scope.privacyDomainId, id()],
        );
        await expect(
          client.query('update control.evidence_stream set last_sequence=99'),
        ).rejects.toThrow('PC-DATA-6007');
        await client.query('rollback');
      } finally {
        client.release();
      }
      const publicUrl = new URL(workerUrl!);
      publicUrl.username = 'openpc_configuration_runtime';
      const publicPool = new Pool({ connectionString: publicUrl.href, max: 1 });
      try {
        await expect(
          publicPool.query('select encrypted_segment from control.evidence_segment_payload'),
        ).rejects.toThrow('permission denied');
        await expect(
          publicPool.query('insert into control.evidence_checkpoint default values'),
        ).rejects.toThrow('permission denied');
      } finally {
        await publicPool.end();
      }
      // Public read-owner segment: real Identity authorization and scoped SQL,
      // with the above explicitly fixture-origin custody population.
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
        { existingScope: true },
      );
      const firstPage = await fixture.read('evidence-records?limit=2');
      expect(firstPage.status, JSON.stringify(firstPage.body)).toBe(200);
      expect(firstPage.headers.get('cache-control')).toBe('no-store');
      expect(firstPage.body).toMatchObject({
        total: '6',
        authorizedEmpty: false,
        completeness: 'COMPLETE',
      });
      expect(firstPage.body.items).toHaveLength(2);
      expect(Object.keys(firstPage.body.items[0]).sort()).toEqual(
        [
          'createdAt',
          'evidenceClass',
          'evidenceId',
          'occurredAt',
          'participantId',
          'recordDigest',
          'revision',
          'sequence',
          'state',
          'updatedAt',
        ].sort(),
      );
      expect(JSON.stringify(firstPage.body)).not.toMatch(
        /receiptBase64|encryptedSegment|source fixture|local-test-key/u,
      );
      const secondPage = await fixture.read(
        `evidence-records?limit=2&cursor=${encodeURIComponent(firstPage.body.nextCursor)}`,
      );
      expect(secondPage.status).toBe(200);
      expect(
        secondPage.body.items.map((record: { evidenceId: string }) => record.evidenceId),
      ).not.toContain(firstPage.body.items[0].evidenceId);
      const record = firstPage.body.items[0];
      expect(await fixture.read(`evidence-records/${record.evidenceId}`)).toMatchObject({
        status: 200,
        body: record,
      });
      expect(
        await fixture.read('evidence-records?filter=evidenceClass:eq:AUTHENTICATION'),
      ).toMatchObject({ status: 200, body: { total: '2' } });
      expect((await fixture.read('evidence-records?filter=receiptBase64:eq:secret')).status).toBe(
        400,
      );
      expect((await fixture.read('evidence-records', { Cookie: '' })).status).toBe(401);
      await fixture.restartConfiguration();
      expect(await fixture.read(`evidence-records/${record.evidenceId}`)).toMatchObject({
        status: 200,
        body: record,
      });
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect(await foreign.read('evidence-records')).toMatchObject({
        status: 200,
        body: { total: '0', items: [], authorizedEmpty: true },
      });
      expect((await foreign.read(`evidence-records/${record.evidenceId}`)).status).toBe(404);
      expect(
        (
          await foreign.read(
            `evidence-records?cursor=${encodeURIComponent(firstPage.body.nextCursor)}`,
          )
        ).status,
      ).toBe(400);
    } finally {
      await foreign?.close();
      await fixture?.close();
      encryption.key.fill(0);
      await admin
        .query(
          'drop trigger if exists test_evidence_checkpoint_failure on control.evidence_checkpoint; drop function if exists openpc.test_evidence_checkpoint_failure()',
        )
        .catch(() => undefined);
      await worker.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  30000,
);
