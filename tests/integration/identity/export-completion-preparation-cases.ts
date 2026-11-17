import { assertNotificationWorkerAdmissionCases } from './notification-worker-admission-cases.js';
import {
  withNotificationWorkerPeer,
  assertNotificationWorkerAdmission,
  type NotificationWorkerAdmission,
} from '../../../services/identity-service/src/domain/notification-worker.js';
import { notificationWorkerSelector } from '../../../services/control-api/src/notifications/worker-installation.js';
import { assertPublishedNotificationSourceReadbackCases } from './notification-source-readback-cases.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import { publishEvidenceExportCompletion } from '../../../services/control-api/src/evidence/export-completion-publication.js';
import { signEvidenceExportCompletion } from '../../../packages/security-kernel/src/index.js';
import { observeEvidenceExportCompletion } from '../../../services/control-api/src/evidence/export-completion-observation.js';
import type { TLSSocket } from 'node:tls';
import { generateKeyPairSync } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';
import { expect } from 'vitest';
import { z } from 'zod';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  prepareEvidenceExportCompletion,
  readPreparedEvidenceExportCompletion,
} from '../../../services/control-api/src/evidence/export-completion.js';
import {
  installEvidenceExportProducer,
  withdrawEvidenceExportProducer,
} from '../../../services/control-api/src/evidence/export-producer-installation.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import type { EvidenceScope } from '../../../services/control-api/src/evidence/segment.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';

/** Joins the existing genuine governed export; initial workload/public-key trust
 * is the only fixture state. No export, approval, completion or result is seeded. */
export async function assertExportCompletionPreparationCases(
  admin: Pool,
  reader: Pool,
  scope: EvidenceScope,
  evidenceExportId: string,
  foreignScope: EvidenceScope,
) {
  const runtime = new Pool({
    connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
    max: 2,
  });
  const installer = new Pool({
    connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL!,
    options: '-c role=openpc_control_owner',
    max: 1,
  });
  const workloadId = `urn:openpc:workload:${id()}`,
    principalId = id(),
    credentialId = id();
  const tls = await runtimeSnapshotTlsFixture(
    `urn:openpc:participant:${scope.participantId}:workload:${workloadId.slice(-36)}`,
  );
  let app: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
  const scoped = async <T>(
    pool: Pool,
    action: (client: PoolClient) => Promise<T>,
    privacy = scope.privacyDomainId,
  ) => {
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
        [scope.participantId, privacy, id()],
      );
      const result = await action(client);
      await client.query('commit');
      return result;
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  };
  try {
    const tlsKey = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
    await admin.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Export completion producer','ACTIVE',1)`,
      [principalId, scope.participantId],
    );
    await admin.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-export-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
      [
        credentialId,
        scope.participantId,
        principalId,
        `urn:openpc:participant:${scope.participantId}:workload:${workloadId.slice(-36)}`,
        workloadId,
        Buffer.from(sha256(tlsKey).slice(7), 'hex'),
        tlsKey,
        Buffer.from(sha256(tls.parsed.raw).slice(7), 'hex'),
        new Date(tls.parsed.validFrom),
        new Date(tls.parsed.validTo),
      ],
    );
    const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const spki = signer.publicKey.export({
      type: 'spki',
      format: 'der',
    });
    const now = BigInt(Date.now()) * 1000000n;
    const trustDigest = await installEvidenceExportProducer(installer, {
      owner: 'LS-EVIDENCE-EXPORT',
      purpose: 'pc.cose.evidence-export-completion-receipt.v1',
      environmentId: 'local-export',
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      sourceId: id(),
      principalId,
      workloadCredentialId: credentialId,
      workloadEpoch: '1',
      workloadId,
      secretClass: 'SECRET-SIGNING-KEY',
      secretReference: 'secret://export-test/completion#v1',
      secretVersion: 'v1',
      publicKeySpkiHex: spki.toString('hex'),
      keyEpoch: '1',
      validFromNs: String(now - 1000000000n),
      validUntilNs: String(now + 600000000000n),
      installationReference: 'local-initial-trust',
    });
    const input = { ...scope, trustDigest, evidenceExportId };
    const openServer = async () => {
      const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
      app = buildLocalWorkloadMtlsService(runtime, kernel, tls.server);
      app.post('/test/notification-worker', async (req, reply) => {
        try {
          const selected = notificationWorkerSelector.parse(req.body);
          let retained: { admission: NotificationWorkerAdmission; client: PoolClient } | undefined;
          const result = await withNotificationWorkerPeer(
            runtime,
            kernel,
            req.raw.socket as TLSSocket,
            selected,
            async (client, admission) => {
              assertNotificationWorkerAdmission(admission, client, selected);
              expect(() =>
                assertNotificationWorkerAdmission({ ...admission }, client, selected),
              ).toThrow();
              expect(Object.isFrozen(admission.installation.input.pins)).toBe(true);
              retained = { admission, client };
              return {
                serviceId: admission.installation.profile.serviceId,
                processRole: admission.installation.profile.processRole,
                installationDigest: admission.installation.installationDigest,
                authorityDigest: admission.authorityDigest,
              };
            },
          );
          expect(retained).toBeDefined();
          expect(() =>
            assertNotificationWorkerAdmission(retained!.admission, retained!.client, selected),
          ).toThrow();
          return result;
        } catch {
          return reply.code(403).send({ code: 'NOTIFICATION_WORKER_UNAVAILABLE' });
        }
      });
      app.post('/test/export-completion', async (req, reply) => {
        try {
          const original = await prepareEvidenceExportCompletion(
            runtime,
            kernel,
            req.raw.socket as TLSSocket,
            req.body,
          );
          return {
            state: original.state,
            eventId: original.claims.eventId,
            payloadDigest: original.receiptPayloadDigest,
          };
        } catch {
          return reply.code(403).send({ code: 'EXPORT_COMPLETION_UNAVAILABLE' });
        }
      });
      app.post('/test/export-completion-observation', async (req, reply) => {
        try {
          const original = await observeEvidenceExportCompletion(
            runtime,
            kernel,
            req.raw.socket as TLSSocket,
            req.body,
          );
          return {
            state: original.state,
            eventId: original.claims.eventId,
            coseDigest: sha256(original.coseSign1!),
          };
        } catch {
          return reply.code(403).send({ code: 'EXPORT_COMPLETION_UNAVAILABLE' });
        }
      });
      app.post('/test/export-completion-publication', async (req, reply) => {
        try {
          const original = await publishEvidenceExportCompletion(
            runtime,
            kernel,
            req.raw.socket as TLSSocket,
            req.body,
          );
          return {
            state: original.state,
            eventId: original.claims.eventId,
            coseDigest: sha256(original.coseSign1!),
          };
        } catch {
          return reply.code(403).send({ code: 'EXPORT_COMPLETION_UNAVAILABLE' });
        }
      });
      return app.listen({ host: '127.0.0.1', port: 0 });
    };
    const snapshot = () =>
      admin
        .query(
          `select
      (select count(*)::integer from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3) events,
      (select encode(sha256(artifact),'hex') from control.evidence_export_output where evidence_export_id=$3) artifact,
      (select count(*)::integer from control.evidence_export_completion where participant_id=$1 and privacy_domain_id=$2) completions`,
          [scope.participantId, scope.privacyDomainId, evidenceExportId],
        )
        .then((r) => r.rows[0]);
    const before = await snapshot();
    let address = await openServer();
    await assertNotificationWorkerAdmissionCases({
      runtime,
      installer,
      scope,
      principalId,
      credentialId,
      workloadId,
      tlsSpki: tlsKey,
      producerTrustDigest: trustDigest,
      call: (value, missingTls) =>
        missingTls
          ? tls.post(`${address}/test/notification-worker`, value, null)
          : tls.post(`${address}/test/notification-worker`, value),
      restart: async () => {
        await app!.close();
        address = await openServer();
      },
    });
    for (const changed of [
      { ...input, evidenceExportId: id() },
      { ...input, privacyDomainId: id() },
      { ...input, streamId: 'foreign' },
    ]) {
      expect(await tls.post(`${address}/test/export-completion`, changed)).toMatchObject({
        status: 403,
      });
      expect(await snapshot()).toEqual(before);
    }
    await expect(tls.post(`${address}/test/export-completion`, input, null)).rejects.toThrow();
    const [first, second] = await Promise.all([
      tls.post(`${address}/test/export-completion`, input),
      tls.post(`${address}/test/export-completion`, input),
    ]);
    expect(first).toMatchObject({ status: 200, body: { state: 'PREPARED' } });
    expect(second).toEqual(first);
    const response = z
      .strictObject({
        state: z.literal('PREPARED'),
        eventId: z.uuidv7(),
        payloadDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
      })
      .parse(first.body);
    const retained = await scoped(reader, (c) =>
      readPreparedEvidenceExportCompletion(c, scope, evidenceExportId),
    );
    expect(retained?.claims.eventId).toBe(response.eventId);
    expect(retained?.claims.sequence).toBe('1');
    expect(await snapshot()).toEqual({ ...before, completions: before.completions + 1 });
    await app!.close();
    address = await openServer();
    expect(await tls.post(`${address}/test/export-completion`, input)).toEqual(first);
    expect(
      await scoped(reader, (c) => readPreparedEvidenceExportCompletion(c, scope, evidenceExportId)),
    ).toEqual(retained);
    expect(
      await scoped(reader, (c) =>
        readPreparedEvidenceExportCompletion(
          c,
          { ...scope, privacyDomainId: id() },
          evidenceExportId,
        ),
      ),
    ).toBeUndefined();
    for (const pool of [runtime, reader]) {
      await expect(
        scoped(pool, (c) =>
          c.query(
            `update control.evidence_export_completion set state='OBSERVED',cose_sign1=$2 where event_id=$1`,
            [retained!.claims.eventId, Buffer.from('invented')],
          ),
        ),
      ).rejects.toThrow(pool === runtime ? 'PC-DATA-6007' : 'permission denied');
      await expect(
        scoped(pool, (c) =>
          c.query(`delete from control.evidence_export_completion where event_id=$1`, [
            retained!.claims.eventId,
          ]),
        ),
      ).rejects.toThrow('permission denied');
    }
    const originalRow = (
      await admin.query<{ row: Record<string, unknown> }>(
        'select to_jsonb(c) row from control.evidence_export_completion c where event_id=$1',
        [retained!.claims.eventId],
      )
    ).rows[0]!.row;
    for (const [change, rejection] of [
      [{ state: 'OBSERVED', cose_sign1: '\\x01' }, 'PC-AUTH-0005'],
      [
        { claims: { ...retained!.claims, outputDigest: sha256('forged-output') } },
        'DATA-6021-EXPORT-COMPLETION-BINDING',
      ],
      [{ authority_snapshot: '\\x7b7d' }, 'PC-AUTH-0005-EXPORT-COMPLETION-AUTHORITY'],
      [{ source_data: '\\xa0' }, 'DATA-6021-EXPORT-COMPLETION-BINDING'],
      [{ receipt_payload: '\\xa0' }, 'DATA-6021-EXPORT-COMPLETION-PAYLOAD'],
      [{ event_payload: '\\x7b7d' }, 'DATA-6021-EXPORT-COMPLETION-EVENT'],
      [{ stream_id: 'foreign' }, 'DATA-6021-EXPORT-COMPLETION-BINDING'],
      [{ privacy_domain_id: id() }, 'PC-AUTH-0005'],
    ] as const) {
      await expect(
        scoped(runtime, (c) =>
          c.query(
            'insert into control.evidence_export_completion select * from jsonb_populate_record(null::control.evidence_export_completion,$1::jsonb)',
            [{ ...originalRow, ...change }],
          ),
        ),
      ).rejects.toThrow(rejection);
      expect(await snapshot()).toEqual({ ...before, completions: before.completions + 1 });
    }
    // Only the external signer is a fixture: the producer TLS peer, current
    // Identity, governed source, SQL observation and restart readback are real.
    const key = signer.privateKey.export({ type: 'pkcs8', format: 'der' });
    const cose = signEvidenceExportCompletion(retained!.claims, key, spki);
    const alternate = signEvidenceExportCompletion(retained!.claims, key, spki);
    key.fill(0);
    expect(alternate).not.toEqual(cose);
    const observation = { ...input, coseHex: cose.toString('hex') };
    const damaged = Buffer.from(cose);
    damaged[damaged.length - 1]! ^= 1;
    for (const changed of [
      { ...observation, coseHex: damaged.toString('hex') },
      { ...observation, coseHex: '00' },
      { ...observation, privacyDomainId: id() },
      { ...observation, evidenceExportId: id() },
      { ...observation, trustDigest: sha256('wrong-producer') },
      { ...observation, claims: retained!.claims },
    ]) {
      expect(
        await tls.post(`${address}/test/export-completion-observation`, changed),
      ).toMatchObject({ status: 403 });
      expect(
        await scoped(reader, (c) =>
          readPreparedEvidenceExportCompletion(c, scope, evidenceExportId),
        ),
      ).toEqual(retained);
    }
    await expect(
      tls.post(`${address}/test/export-completion-observation`, observation, null),
    ).rejects.toThrow();
    expect(await tls.post(`${address}/test/export-completion-publication`, input)).toMatchObject({
      status: 403,
    });
    const results = await Promise.all([
      tls.post(`${address}/test/export-completion-observation`, observation),
      tls.post(`${address}/test/export-completion-observation`, observation),
    ]);
    expect(results[0]).toEqual(results[1]);
    expect(results[0]).toMatchObject({
      status: 200,
      body: { state: 'OBSERVED', eventId: retained!.claims.eventId, coseDigest: sha256(cose) },
    });
    const observed = await scoped(reader, (c) =>
      readPreparedEvidenceExportCompletion(c, scope, evidenceExportId),
    );
    expect(observed).toEqual({ ...retained, state: 'OBSERVED', coseSign1: cose });
    expect(
      await tls.post(`${address}/test/export-completion-observation`, {
        ...observation,
        coseHex: alternate.toString('hex'),
      }),
    ).toMatchObject({ status: 403 });
    await expect(
      scoped(runtime, (c) =>
        c.query(
          "update control.evidence_export_completion set state='PUBLISHED' where event_id=$1",
          [retained!.claims.eventId],
        ),
      ),
    ).rejects.toThrow('DATA-6021-EXPORT-PUBLICATION-INCOMPLETE');
    await app!.close();
    address = await openServer();
    expect(await tls.post(`${address}/test/export-completion-observation`, observation)).toEqual(
      results[0],
    );
    expect(await snapshot()).toEqual({ ...before, completions: before.completions + 1 });
    await expect(
      scoped(runtime, (c) =>
        c.query(
          `
      insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,
        aggregate_id,business_sequence,proof_kind,sequence_namespace,data_schema_uri,source,subject,
        correlation_id,causation_id,payload_cbor,payload_digest,occurred_at)
      select participant_id,privacy_domain_id,event_id,'io.openpc.evidence.export.completed.v1','evidence-export',
        evidence_export_id,1,'EVIDENCE_EXPORT_COMPLETION_REFERENCE','EVIDENCE_EXPORT_COMPLETION_V1',
        'https://schemas.openpc.local/event-payloads.schema.json#/$defs/EvidenceExportCompleted',
        'urn:openpc:service:'||(claims->>'sourceId'),'urn:openpc:resource:'||evidence_export_id::text,
        (claims->>'startOperationId')::uuid,(claims->>'causationId')::uuid,source_data,sha256(source_data),
        (convert_from(event_payload,'UTF8')::jsonb->>'time')::timestamptz
      from control.evidence_export_completion where event_id=$1`,
          [retained!.claims.eventId],
        ),
      ),
    ).rejects.toThrow('DATA-6021-EXPORT-PUBLICATION-INCOMPLETE');
    expect(await snapshot()).toEqual({ ...before, completions: before.completions + 1 });
    expect(
      await scoped(reader, (c) => readPreparedEvidenceExportCompletion(c, scope, evidenceExportId)),
    ).toEqual(observed);
    const publications = await Promise.all([
      tls.post(`${address}/test/export-completion-publication`, input),
      tls.post(`${address}/test/export-completion-publication`, input),
    ]);
    expect(publications[0]).toEqual(publications[1]);
    expect(publications[0]).toMatchObject({
      status: 200,
      body: { state: 'PUBLISHED', eventId: retained!.claims.eventId, coseDigest: sha256(cose) },
    });
    const published = await scoped(reader, (c) =>
      readPreparedEvidenceExportCompletion(c, scope, evidenceExportId),
    );
    expect(published).toEqual({ ...observed, state: 'PUBLISHED' });
    expect(await snapshot()).toEqual({
      ...before,
      events: before.events + 1,
      completions: before.completions + 1,
    });
    const eventRow = (
      await admin.query<{ row: Record<string, unknown> }>(
        'select to_jsonb(e) row from control.outbox_event e where event_id=$1',
        [retained!.claims.eventId],
      )
    ).rows[0]!.row;
    expect(eventRow.proof_kind).toBe('EVIDENCE_EXPORT_COMPLETION_REFERENCE');
    expect(eventRow.sequence_namespace).toBe('EVIDENCE_EXPORT_COMPLETION_V1');
    expect(eventRow.receipt_id).toBeNull();
    expect(eventRow.cose_sign1).toBeNull();
    expect(eventRow).toMatchObject({
      participant_id: scope.participantId,
      privacy_domain_id: scope.privacyDomainId,
      event_id: retained!.claims.eventId,
      aggregate_type: 'evidence-export',
      aggregate_id: evidenceExportId,
      event_type: 'io.openpc.evidence.export.completed.v1',
      business_sequence: 1,
      payload_cbor: '\\x' + retained!.sourceData.toString('hex'),
      payload_digest: '\\x' + retained!.claims.dataDigest.slice(7),
      correlation_id: retained!.claims.startOperationId,
      causation_id: retained!.claims.causationId,
      source: 'urn:openpc:service:' + retained!.claims.sourceId,
      subject: 'urn:openpc:resource:' + evidenceExportId,
      data_schema_uri:
        'https://schemas.openpc.local/event-payloads.schema.json#/$defs/EvidenceExportCompleted',
    });
    for (const change of [
      { payload_cbor: '\\x00' },
      { payload_digest: '\\x00' },
      { business_sequence: 2 },
      { business_sequence: null },
      { correlation_id: id() },
      { causation_id: id() },
      { aggregate_id: id() },
      { event_type: 'io.openpc.control.command.committed.v1' },
      { source: 'urn:openpc:service:' + id() },
      { subject: 'urn:openpc:resource:' + id() },
      { occurred_at: new Date().toISOString() },
      { sequence_namespace: 'CONTROL_BUSINESS_TRANSITION_V1' },
    ])
      await expect(
        scoped(runtime, (c) =>
          c.query(
            'insert into control.outbox_event select * from jsonb_populate_record(null::control.outbox_event,$1::jsonb)',
            [{ ...eventRow, outbox_event_id: id(), ...change }],
          ),
        ),
      ).rejects.toThrow('DATA-6021-EXPORT-COMPLETION-OUTBOX');
    await expect(
      scoped(runtime, (c) =>
        c.query('delete from control.outbox_event where event_id=$1', [retained!.claims.eventId]),
      ),
    ).rejects.toThrow();
    await assertPublishedNotificationSourceReadbackCases({
      selector: { scope, evidenceExportId, eventId: published!.claims.eventId },
      original: {
        payload: published!.receiptPayload,
        cose: published!.coseSign1!,
        envelope: JSON.parse(published!.eventPayload.toString('utf8')),
      },
      foreignScope,
      withRuntimeTransaction: async (selected, run) => {
        const client = await runtime.connect();
        try {
          await client.query('begin');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            [selected.participantId, selected.privacyDomainId, id()],
          );
          await lockEvidenceLifecycle(client, selected.participantId, selected.privacyDomainId);
          const result = await run(client);
          await client.query('commit');
          return result;
        } catch (error) {
          await client.query('rollback');
          throw error;
        } finally {
          client.release();
        }
      },
      restart: async () => {
        await app!.close();
        address = await openServer();
      },
    });
    expect(await tls.post(`${address}/test/export-completion-publication`, input)).toEqual(
      publications[0],
    );
    expect(
      await scoped(reader, (c) => readPreparedEvidenceExportCompletion(c, scope, evidenceExportId)),
    ).toEqual(published);
    await withdrawEvidenceExportProducer(installer, scope, trustDigest);
    expect(await tls.post(`${address}/test/export-completion`, input)).toMatchObject({
      status: 403,
    });
    expect(
      await tls.post(`${address}/test/export-completion-observation`, observation),
    ).toMatchObject({ status: 403 });
    expect(
      await scoped(reader, (c) => readPreparedEvidenceExportCompletion(c, scope, evidenceExportId)),
    ).toEqual(published);
    expect(await tls.post(`${address}/test/export-completion-publication`, input)).toMatchObject({
      status: 403,
    });
    expect(await snapshot()).toEqual({
      ...before,
      events: before.events + 1,
      completions: before.completions + 1,
    });
    process.stdout.write(
      'OPENPC_EXPORT_COMPLETION|PUBLISHED|real-tls-governed-source|concurrent-original|exact-cose|single-bound-outbox|restart-readback|revoked-no-new-observation-or-publication\n',
    );
  } finally {
    await app?.close();
    await tls.close();
    await runtime.end();
    await installer.end();
  }
}
