import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { archiveProtectedProof } from '../../../services/control-api/src/evidence/protected-custody.js';
import { LocalProtectedProofVault } from '../../../services/control-api/src/evidence/protected-vault.js';
import { protectedConsumptionResponse } from '../../../services/control-api/src/evidence/protected-contracts.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;
const time = (offset: number) =>
  new Date(Date.now() + offset).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
// SEM-138/139: real committed WebAuthn source, exact encrypted retention, existing
// maker/checker and fresh step-up, one-use sender-bound delivery and durable readback.
integration(
  'retains and discloses the exact Identity proof once through real governed owners',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'protected-source' };
    const archiveRoot = await mkdtemp(
      join(process.env.OPENPC_TEST_TMP_ROOT!, 'protected-custody-'),
    );
    const keys = {
      activeKeyId: 'proof-test-key',
      keys: new Map([['proof-test-key', randomBytes(32)]]),
    };
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
        { protectedProofKeys: keys },
      );
      const { client, maker } = fixture.governance;
      await client.stepUp(
        maker,
        'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
        id(),
        sha256({ purpose: 'authentication source' }),
      );
      const custody = new EvidenceCustody(worker);
      await custody.ingestAuthentication(
        scope,
        { keyId: 'ordinary-custody', key: randomBytes(32) },
        time(86400000),
        1048576,
      );
      const sourceRow = (
        await admin.query(
          `select c.evidence_id::text id from control.evidence_catalogue c
      join control.authentication_occurrence a on a.occurrence_id::text=c.record_id
      where c.participant_id=$1 and c.privacy_domain_id=$2 and a.method='WEBAUTHN_ASSERTION'
      order by c.sequence desc limit 1`,
          [scope.participantId, scope.privacyDomainId],
        )
      ).rows[0];
      expect(sourceRow).toBeDefined();
      const sourceRef = `urn:openpc:resource:${sourceRow.id}`;
      const discovery = await fixture.read(`evidence-records/${sourceRef}/protected-proof-source`);
      expect(discovery, JSON.stringify(discovery)).toMatchObject({
        status: 200,
        body: {
          materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
          evidenceClass: 'AUTHENTICATION',
          finality: 'NOT_APPLICABLE',
          authorityEffect: 'NONE',
        },
      });
      expect(discovery.headers.get('cache-control')).toBe('no-store');
      expect(discovery.body).not.toHaveProperty('assertionBase64');
      const retainAction = 'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1';
      const retain = await fixture.prepareMutation(
        'protected-proofs',
        retainAction,
        {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          source: discovery.body,
          purpose: 'Investigate this authentication',
          caseReference: 'case-proof-1',
          retainUntil: time(86400000),
        },
        true,
      );
      expect((await retain.commit()).status).toBe(403);
      await retain.stepUp();
      const retained = await retain.commit();
      expect(retained, JSON.stringify(retained)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      expect((await retain.commit()).body).toEqual(retained.body);
      const objectRef = String(retained.body.resourceRef);
      const object = await fixture.read(`protected-proofs/${objectRef}`);
      expect(object).toMatchObject({
        status: 200,
        body: { objectRef, objectVersion: '1', source: discovery.body },
      });
      expect(JSON.stringify(object.body)).not.toMatch(
        /assertionBase64|coseSign1Base64|ciphertext|nonce|keyId/u,
      );
      const binding = {
        objectRef,
        objectVersion: '1',
        objectDigest: object.body.objectDigest,
        source: object.body.source,
      };
      const originals = (
        await admin.query(
          `select e.evidence_cbor,e.cose_sign1 from control.mutation_evidence e
      where e.participant_id=$1 and e.operation_id=$2`,
          [scope.participantId, discovery.body.operationId],
        )
      ).rows[0];
      const ciphertext = (
        await admin.query(
          `select ciphertext from control.protected_proof_payload where object_id=$1`,
          [objectRef.slice(-36)],
        )
      ).rows[0].ciphertext as Buffer;
      expect(ciphertext.includes(originals.evidence_cbor)).toBe(false);
      const rawScope = {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
      };
      const archive = await LocalProtectedProofVault.open(archiveRoot, 'protected-test');
      const originalPut = archive.put.bind(archive);
      archive.put = async (...args) => {
        await originalPut(...args);
        throw new Error('simulated lost archive acknowledgement');
      };
      await expect(archiveProtectedProof(worker, rawScope, archive)).rejects.toThrow(
        'lost archive acknowledgement',
      );
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.protected_proof_checkpoint where object_id=$1',
            [objectRef.slice(-36)],
          )
        ).rows[0].n,
      ).toBe(0);
      const restartedArchive = await LocalProtectedProofVault.open(archiveRoot, 'protected-test');
      expect(await archiveProtectedProof(worker, rawScope, restartedArchive)).toMatchObject({
        objectRef,
        objectVersion: '1',
        assurance: 'LOCAL_FSYNC_READBACK',
      });
      expect(await archiveProtectedProof(worker, rawScope, restartedArchive)).toBeNull();
      const checkpoints = await admin.query(
        'select * from control.protected_proof_checkpoint where object_id=$1',
        [objectRef.slice(-36)],
      );
      expect(checkpoints.rowCount).toBe(1);
      const checkpoint = checkpoints.rows[0]!;
      expect(checkpoint.receipt.object).toMatchObject({
        dataClass: 'RAW_SOURCE_BODY',
        ...rawScope,
        ...binding,
      });
      const archivedPayload = await restartedArchive.read(checkpoint.receipt.object);
      expect(Buffer.from(archivedPayload.ciphertextBase64, 'base64')).toEqual(ciphertext);
      expect(checkpoint.payload_digest).toBe(sha256(archivedPayload));
      const workerClient = await worker.connect();
      try {
        await workerClient.query('begin');
        await workerClient.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, scope.privacyDomainId, id()],
        );
        await expect(
          workerClient.query(
            'update control.protected_proof_checkpoint set receipt_digest=$1 where object_id=$2',
            [sha256('forged'), objectRef.slice(-36)],
          ),
        ).rejects.toMatchObject({ code: '42501' });
        await workerClient.query('rollback');
        await workerClient.query('begin');
        await workerClient.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, scope.privacyDomainId, id()],
        );
        await expect(
          workerClient.query(
            `insert into control.protected_proof_checkpoint
          (participant_id,privacy_domain_id,object_id,sink_id,payload_digest,ciphertext_bytes,receipt,receipt_digest,checkpoint_digest)
          values($1,$2,$3,'forged', $4,$5,$6,$7,$8)`,
            [
              scope.participantId,
              scope.privacyDomainId,
              objectRef.slice(-36),
              checkpoint.payload_digest,
              checkpoint.ciphertext_bytes,
              checkpoint.receipt,
              checkpoint.receipt_digest,
              checkpoint.checkpoint_digest,
            ],
          ),
        ).rejects.toMatchObject({ code: 'P0001' });
        await workerClient.query('rollback');
        await workerClient.query('begin');
        await workerClient.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, id(), id()],
        );
        expect(
          (await workerClient.query('select object_id from control.protected_proof_checkpoint'))
            .rowCount,
        ).toBe(0);
        expect(
          (await workerClient.query('select object_id from control.protected_proof_payload'))
            .rowCount,
        ).toBe(0);
        await workerClient.query('rollback');
      } finally {
        await workerClient.query('rollback').catch(() => undefined);
        workerClient.release();
      }
      const requestAction = 'ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1';
      const requestFields = {
        participantId: `urn:openpc:participant:${scope.participantId}`,
        object: binding,
        purpose: 'Investigate this authentication',
        caseReference: 'case-proof-1',
        recipientPrincipalId: maker.principalId,
        expiresAt: time(240000),
      };
      const access = await fixture.prepareMutation(
        'protected-proof-access',
        requestAction,
        requestFields,
        true,
      );
      expect((await access.commit()).status).toBe(403);
      await access.stepUp();
      const requested = await access.commit();
      expect(requested, JSON.stringify(requested)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      const accessRef = String(requested.body.resourceRef),
        consumeAction = 'ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1';
      const { participantId: unused, ...boundRequest } = requestFields;
      void unused;
      const consumeFields = { ...boundRequest, targetRef: accessRef, expectedRevision: '1' };
      for (const change of [
        { purpose: 'another purpose' },
        { caseReference: 'another case' },
        { recipientPrincipalId: fixture.governance.checker.principalId },
        { object: { ...binding, objectDigest: `sha256:${'0'.repeat(64)}` } },
        { object: { ...binding, objectVersion: '2' } },
        { object: { ...binding, source: { ...binding.source, operationId: id() } } },
      ]) {
        const denied = await fixture.attemptMutation(
          `protected-proof-access/${accessRef}/consume`,
          consumeAction,
          { ...consumeFields, ...change },
        );
        expect(denied.status, JSON.stringify(denied)).toBeGreaterThanOrEqual(400);
        expect((await fixture.read(`protected-proof-access/${accessRef}`)).body.state).toBe(
          'AVAILABLE',
        );
      }
      const delivery = fixture.ordinaryMutation(
        `protected-proof-access/${accessRef}/consume`,
        consumeAction,
        consumeFields,
      );
      const encryptionKey = keys.keys.get(keys.activeKeyId)!;
      keys.keys.set(keys.activeKeyId, randomBytes(32));
      try {
        expect((await delivery.call()).status).toBe(412);
        expect((await fixture.read(`protected-proof-access/${accessRef}`)).body.state).toBe(
          'AVAILABLE',
        );
      } finally {
        keys.keys.set(keys.activeKeyId, encryptionKey);
      }
      // Failure after decrypt/update but before durable audit must release nothing
      // and leave the same approved intent recoverable.
      await admin.query(`create function openpc.test_protected_audit_failure() returns trigger language plpgsql as $$
        begin if NEW.event_type='openpc.evidence.protected.consumed.v1' then raise exception 'PC-OPS-9002'; end if; return NEW; end $$;
        create trigger test_protected_audit_failure before insert on control.outbox_event
        for each row execute function openpc.test_protected_audit_failure()`);
      try {
        const failed = await delivery.call();
        expect(failed.status).toBeGreaterThanOrEqual(400);
        expect(failed.body).not.toHaveProperty('disclosure');
        expect((await fixture.read(`protected-proof-access/${accessRef}`)).body.state).toBe(
          'AVAILABLE',
        );
      } finally {
        await admin.query(
          'drop trigger test_protected_audit_failure on control.outbox_event; drop function openpc.test_protected_audit_failure()',
        );
      }
      const results = await Promise.all([delivery.call(), delivery.call()]);
      const delivered = results.find(
        (result) => result.status === 202 && result.body.disclosure !== null,
      );
      expect(delivered, JSON.stringify(results)).toBeDefined();
      expect(
        results.filter((result) => result.status === 202 && result.body.disclosure !== null),
      ).toHaveLength(1);
      expect(delivered!.body.disclosure).toEqual({
        version: 'OPENPC_PROTECTED_IDENTITY_PROOF_V1',
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        source: discovery.body,
        assertionBase64: originals.evidence_cbor.toString('base64'),
        coseSign1Base64: originals.cose_sign1.toString('base64'),
      });
      expect(sha256(Buffer.from(canonicalJson(delivered!.body.disclosure)))).toBe(
        object.body.objectDigest,
      );
      // A caller can lose the response after commit; the operation/readback survives,
      // but neither exact replay nor another key can release the original bytes again.
      await fixture.restartConfiguration();
      expect(await delivery.call()).toMatchObject({
        status: 202,
        body: { operation: delivered!.body.operation, disclosure: null },
      });
      expect(
        (
          await fixture.attemptMutation(
            `protected-proof-access/${accessRef}/consume`,
            consumeAction,
            consumeFields,
          )
        ).status,
      ).toBeGreaterThanOrEqual(400);
      const recovered = await fixture.read(`protected-proof-access/${accessRef}`);
      const deliveredResult = protectedConsumptionResponse.parse(delivered!.body);
      expect(recovered).toMatchObject({
        status: 200,
        body: {
          state: 'CONSUMED',
          revision: '2',
          consumptionOperationId: deliveredResult.operation.operationId,
        },
      });
      const persisted = (
        await admin.query(
          `select result_payload from control.idempotency_record where participant_id=$1
      and operation_id=$2`,
          [scope.participantId, deliveredResult.operation.operationId],
        )
      ).rows[0].result_payload;
      expect(persisted).toEqual(delivered!.body.operation);
      expect(JSON.stringify(persisted)).not.toContain(originals.evidence_cbor.toString('base64'));
      const expiringFields = {
        ...requestFields,
        caseReference: 'expiry-case',
        expiresAt: time(4000),
      };
      const expiring = await fixture.prepareMutation(
        'protected-proof-access',
        requestAction,
        expiringFields,
        true,
      );
      await expiring.stepUp();
      const expiringResult = await expiring.commit();
      expect(expiringResult.status, JSON.stringify(expiringResult)).toBe(202);
      const expiringRef = String(expiringResult.body.resourceRef);
      await delay(Math.max(0, Date.parse(expiringFields.expiresAt) - Date.now() + 25));
      expect((await fixture.read(`protected-proof-access/${expiringRef}`)).body.state).toBe(
        'EXPIRED',
      );
      expect(
        (
          await fixture.attemptMutation(
            `protected-proof-access/${expiringRef}/consume`,
            consumeAction,
            {
              ...consumeFields,
              targetRef: expiringRef,
              caseReference: expiringFields.caseReference,
              expiresAt: expiringFields.expiresAt,
            },
          )
        ).status,
      ).toBeGreaterThanOrEqual(400);
      const senderFields = {
        ...requestFields,
        caseReference: 'sender-case',
        expiresAt: time(240000),
      };
      const sender = await fixture.prepareMutation(
        'protected-proof-access',
        requestAction,
        senderFields,
        true,
      );
      await sender.stepUp();
      const senderResult = await sender.commit();
      expect(senderResult.status).toBe(202);
      await fixture.refresh();
      expect(fixture.governance.maker.sessionId).not.toBe(maker.sessionId);
      const senderRef = String(senderResult.body.resourceRef);
      expect(
        (
          await fixture.attemptMutation(
            `protected-proof-access/${senderRef}/consume`,
            consumeAction,
            {
              ...consumeFields,
              targetRef: senderRef,
              caseReference: senderFields.caseReference,
              expiresAt: senderFields.expiresAt,
            },
          )
        ).status,
      ).toBe(403);
      expect((await fixture.read(`protected-proof-access/${senderRef}`)).body.state).toBe(
        'AVAILABLE',
      );
      expect(
        (
          await fixture.read(`protected-proofs/${objectRef}`, {
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${id()}`,
          })
        ).status,
      ).toBeGreaterThanOrEqual(400);
      expect(
        (
          await fixture.read(`protected-proofs/${objectRef}`, {
            'OpenPC-Participant-ID': `urn:openpc:participant:${id()}`,
          })
        ).status,
      ).toBeGreaterThanOrEqual(400);
      expect((await fixture.read(`protected-proofs/${objectRef}`, { Cookie: '' })).status).toBe(
        401,
      );
    } finally {
      await fixture?.close();
      await worker.end();
      await admin.end();
      await rm(archiveRoot, { recursive: true, force: true });
    }
  },
  120000,
);
