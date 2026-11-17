import type { Pool, PoolClient } from 'pg';
import type { FastifyInstance } from 'fastify';
import type { TLSSocket } from 'node:tls';
import { generateKeyPairSync } from 'node:crypto';
import { expect } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationWorkerProfileClaims,
} from '../../../packages/security-kernel/src/index.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import type { IdentityKernel } from '../../../services/identity-service/src/domain/identity-kernel.js';
import {
  withNotificationWorkerPeer,
  withNotificationDeliveryWorkerPeer,
  assertNotificationDeliveryWorkerCurrent,
} from '../../../services/identity-service/src/domain/notification-worker.js';
import {
  installInitialNotificationWorker,
  withdrawNotificationWorker,
} from '../../../services/control-api/src/notifications/worker-installation.js';
import {
  NotificationPayloadReferenceGate,
  assertNotificationPayloadReference,
  assertNotificationDeliveryPayloadReference,
  assertNotificationDeliveryMaterialStage,
  type NotificationDeliveryMaterialStage,
  type NotificationDeliveryPayloadReference,
} from '../../../services/control-api/src/notifications/payload-reference.js';
import type { NotificationKeyPreparation } from '../../../services/control-api/src/evidence/notification-key-contracts.js';
import type { NotificationDeliverySourceSelector } from '../../../services/control-api/src/notifications/delivery-source.js';
import { readPublishedNotificationDeliveryRequest } from '../../../services/control-api/src/notifications/delivery-source.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';

/** Uses the existing real TLS listener, Identity, database and immutable vault.
 * The transaction-local setting is solely a rollback oracle; it is not an occurrence, event,
 * cursor or claim of feature publication acceptance. */
export function mountNotificationPayloadReferenceProbe(
  app: FastifyInstance,
  options: {
    pool: Pool;
    kernel: IdentityKernel;
    vaultDirectory: string;
    callback?: (client: PoolClient) => Promise<void>;
  },
) {
  const gate = new NotificationPayloadReferenceGate(options.vaultDirectory);
  app.post('/test/notification-reference', async (request, reply) => {
    try {
      const value = request.body as Parameters<typeof gate.withCurrent>[2];
      return await withNotificationWorkerPeer(
        options.pool,
        options.kernel,
        request.raw.socket as TLSSocket,
        value.worker,
        async (client, admission) => {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          );
          await client.query(
            "select set_config('openpc.test_notification_reference_probe','0',true)",
          );
          let reference;
          try {
            const result = await gate.withCurrent(client, admission, value, async (current) => {
              reference = current;
              assertNotificationPayloadReference(current, client);
              expect(() =>
                assertNotificationDeliveryPayloadReference(
                  current as NotificationDeliveryPayloadReference,
                  client,
                  {
                    worker: value.worker,
                    notificationOccurrenceId: current.preparation.occurrenceId,
                    eventId: current.preparation.sourceEventId,
                  },
                ),
              ).toThrow();
              expect(() => assertNotificationPayloadReference({ ...current }, client)).toThrow();
              expect(() => assertNotificationPayloadReference(current, {} as PoolClient)).toThrow();
              await client.query(
                "select set_config('openpc.test_notification_reference_probe','1',true)",
              );
              await options.callback?.(client);
              return { keyId: current.reference.keyId, custodyDigest: current.custodyDigest };
            });
            expect(() => assertNotificationPayloadReference(reference!, client)).toThrow();
            return { admitted: true, ...result };
          } catch {
            const rows = await client.query<{ count: number }>(
              "select current_setting('openpc.test_notification_reference_probe')::integer count",
            );
            expect(rows.rows[0]!.count).toBe(0);
            return { admitted: false, callbackRows: rows.rows[0]!.count };
          } finally {
            await client.query(
              "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
            );
          }
        },
      );
    } catch {
      return reply.code(403).send({ code: 'NOTIFICATION_REFERENCE_UNAVAILABLE' });
    }
  });
  app.post('/test/notification-delivery-reference', async (request, reply) => {
    try {
      const value = request.body as NotificationDeliverySourceSelector;
      return await withNotificationDeliveryWorkerPeer(
        options.pool,
        options.kernel,
        request.raw.socket as TLSSocket,
        value.worker,
        async (client, admission) => {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          );
          await client.query(
            "select set_config('openpc.test_notification_reference_probe','0',true)",
          );
          let reference: NotificationDeliveryPayloadReference | undefined;
          let retainedStage: NotificationDeliveryMaterialStage | undefined;
          const attemptLock = (preparationId: string) =>
            runScopedTransaction(
              options.pool,
              {
                participantId: value.worker.participantId,
                privacyDomainId: value.worker.privacyDomainId,
                actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
              },
              id,
              async (probe) => {
                const locked = await probe.query(
                  'select attempt_id from control.evidence_kms_attempt where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 for update nowait',
                  [value.worker.participantId, value.worker.privacyDomainId, preparationId],
                );
                expect(locked.rowCount).toBe(1);
              },
            );
          try {
            const result = await gate.withDeliveryMaterialStage(
              client,
              admission,
              value,
              async (stage) => {
                retainedStage = stage;
                assertNotificationDeliveryMaterialStage(stage, client, value);
                expect(() =>
                  assertNotificationDeliveryMaterialStage({ ...stage }, client, value),
                ).toThrow();
                expect(() =>
                  assertNotificationDeliveryPayloadReference(stage, client, value),
                ).toThrow();
                await assertNotificationDeliveryWorkerCurrent(admission, client, value.worker);
                // Real second connection can take the original attempt during
                // staged preparation. This is a lock-order proof, not an unwrap.
                await attemptLock(stage.preparation.preparationId);
                return gate.withDeliveryCurrent(client, admission, value, async (current) => {
                  reference = current;
                  await expect(attemptLock(stage.preparation.preparationId)).rejects.toThrow(
                    /could not obtain lock/u,
                  );
                  assertNotificationDeliveryPayloadReference(current, client, value);
                  expect(() => assertNotificationPayloadReference(current, client)).toThrow();
                  expect(() =>
                    assertNotificationDeliveryPayloadReference({ ...current }, client, value),
                  ).toThrow();
                  expect(() =>
                    assertNotificationDeliveryPayloadReference(current, {} as PoolClient, value),
                  ).toThrow();
                  expect(() =>
                    assertNotificationDeliveryPayloadReference(current, client, {
                      ...value,
                      eventId: id(),
                    }),
                  ).toThrow();
                  expect(current.preparation.input.kmsInstallationDigest).not.toBe(
                    value.worker.installationDigest,
                  );
                  expect(current.deliverySource.notificationOccurrenceId).toBe(
                    current.preparation.occurrenceId,
                  );
                  expect(current.deliverySource.keyPreparationId).toBe(
                    current.preparation.preparationId,
                  );
                  expect(current.deliverySource.payloadObjectId).toBe(
                    current.preparation.objectIntent.payloadObjectId,
                  );
                  expect(current.deliverySource.payloadDigest).toBe(
                    current.preparation.objectIntent.payloadDigest,
                  );
                  await client.query(
                    "select set_config('openpc.test_notification_reference_probe','1',true)",
                  );
                  await options.callback?.(client);
                  return {
                    keyId: current.reference.keyId,
                    custodyDigest: current.custodyDigest,
                    sourceReceiptDigest: current.deliverySourceReceiptDigest,
                    payloadObjectId: current.preparation.objectIntent.payloadObjectId,
                  };
                });
              },
            );
            expect(() =>
              assertNotificationDeliveryMaterialStage(retainedStage!, client, value),
            ).toThrow();
            expect(() =>
              assertNotificationDeliveryPayloadReference(reference!, client, value),
            ).toThrow();
            expect(() => assertNotificationPayloadReference(reference!, client)).toThrow();
            return { admitted: true, ...result };
          } catch {
            const rows = await client.query<{ count: number }>(
              "select current_setting('openpc.test_notification_reference_probe')::integer count",
            );
            expect(rows.rows[0]!.count).toBe(0);
            if (reference)
              expect(() =>
                assertNotificationDeliveryPayloadReference(reference!, client, value),
              ).toThrow();
            return { admitted: false, callbackRows: rows.rows[0]!.count };
          } finally {
            await client.query(
              "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
            );
          }
        },
      );
    } catch {
      return reply.code(403).send({ code: 'NOTIFICATION_REFERENCE_UNAVAILABLE' });
    }
  });
}

export async function assertNotificationPayloadReferenceCases(input: {
  installer: Pool;
  preparation: NotificationKeyPreparation;
  principalId: string;
  credentialId: string;
  workloadId: string;
  tlsSpki: Buffer;
  call(value: unknown, missingTls?: boolean): Promise<{ status: number; body: unknown }>;
  publish(): Promise<void>;
  refresh(): Promise<void>;
  assertKmsWithdrawalBlocked(): Promise<void>;
  setCallback(value: ((client: PoolClient) => Promise<void>) | undefined): void;
}) {
  const p = input.preparation,
    scope = p.input.scope;
  const scoped = async <T>(run: (client: PoolClient) => Promise<T>) => {
    const c = await input.installer.connect();
    try {
      await c.query('begin');
      await c.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
        [scope.participantId, scope.privacyDomainId, id()],
      );
      const result = await run(c);
      await c.query('commit');
      return result;
    } catch (e) {
      await c.query('rollback');
      throw e;
    } finally {
      c.release();
    }
  };
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const issuerSpki = issuer.publicKey.export({ type: 'spki', format: 'der' }),
    privateKey = issuer.privateKey.export({ type: 'pkcs8', format: 'der' });
  const now = Date.now();
  const claims: NotificationWorkerProfileClaims = {
    environmentId: p.kms.environmentId,
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    profileId: id(),
    revision: '1',
    validFromMs: now - 1000,
    validUntilMs: now + 600000,
    sourceId: id(),
    serviceId: 'LS-NOTIFICATION',
    processRole: 'ROLE-NOTIFICATION-WORKER',
    subscriptionId: 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
    principalId: input.principalId,
    workloadCredentialId: input.credentialId,
    workloadEpoch: '1',
    workloadId: input.workloadId,
    producerTrustDigest: p.input.producerTrustDigest,
    routingProfileDigest: p.input.routing.signedProfileDigest,
    kmsInstallationDigest: p.input.kmsInstallationDigest,
    receiptSignerSpki: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
    issuerKeyId: evidenceKeyId(issuerSpki),
  };
  const signed = signNotificationClaim(
    'NotificationWorkerProfileV1',
    privateKey,
    issuerSpki,
    claims,
  );
  privateKey.fill(0);
  const {
    environmentId,
    participantId,
    privacyDomainId,
    profileId,
    revision,
    serviceId,
    processRole,
    subscriptionId,
    principalId,
    workloadCredentialId,
    workloadEpoch,
    workloadId,
  } = claims;
  const installationDigest = await scoped((client) =>
    installInitialNotificationWorker(client, {
      pins: {
        issuerSpkiHex: issuerSpki.toString('hex'),
        signedProfileDigest: sha256(signed.cose),
        environmentId,
        participantId,
        privacyDomainId,
        profileId,
        revision,
        serviceId,
        processRole,
        subscriptionId,
        principalId,
        workloadCredentialId,
        workloadEpoch,
        workloadId,
        workloadKeyDigest: evidenceKeyId(input.tlsSpki),
      },
      signed: { payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
      installationReference: 'real-notification-payload-reference-test',
    }),
  );
  const worker = { participantId, privacyDomainId, installationDigest },
    selector = { worker, keyPreparationId: p.preparationId };
  const denied = { status: 200, body: { admitted: false, callbackRows: 0 } };
  await expect(input.call(selector, true)).rejects.toThrow();
  expect(
    await input.call({ ...selector, worker: { ...worker, privacyDomainId: id() } }),
  ).toMatchObject({ status: 403 });
  expect(await input.call({ ...selector, keyPreparationId: id() })).toMatchObject(denied);
  expect(await input.call(selector)).toMatchObject(denied); // Source not published.
  await input.publish();
  expect(await input.call(selector)).toMatchObject(denied); // Original pre-key STATUS cannot grant publication.
  await input.refresh();
  expect(await input.call(selector)).toMatchObject({ status: 200, body: { admitted: true } });
  input.setCallback(async () => {
    throw new Error('PRIVATE_CANARY');
  });
  expect(await input.call(selector)).toMatchObject(denied);
  input.setCallback(async () => {
    await new Promise((resolve) => setTimeout(resolve, 5100));
  });
  await input.refresh();
  expect(await input.call(selector)).toMatchObject(denied); // Final expiry rolls callback row back.
  input.setCallback(undefined);
  await input.refresh();
  let entered!: () => void, release!: () => void;
  const arrival = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  input.setCallback(async () => {
    entered();
    await held;
  });
  const pending = input.call(selector);
  try {
    await Promise.race([
      arrival,
      pending.then(() => {
        throw new Error('Gate did not enter callback');
      }),
    ]);
    await expect(scoped((client) => withdrawNotificationWorker(client, worker))).rejects.toThrow();
    await input.assertKmsWithdrawalBlocked();
  } finally {
    release();
  }
  expect(await pending).toMatchObject({ status: 200, body: { admitted: true } });
  input.setCallback(undefined);
  await scoped((client) => withdrawNotificationWorker(client, worker));
  expect(await input.call(selector)).toMatchObject({ status: 403 });
}

/** Consumes the existing installed delivery actor and original publication/key
 * fixture. It neither installs a substitute producer nor seeds a delivery or
 * generation. Only the caller's genuine external KMS owner refreshes STATUS. */
export async function assertNotificationDeliveryPayloadReferenceCases(input: {
  source: NotificationDeliverySourceSelector;
  preparation: NotificationKeyPreparation;
  call(value: unknown, missingTls?: boolean): Promise<{ status: number; body: unknown }>;
  /** A genuine publisher/subscription peer calls the delivery-only route. */
  callPublisher(value: unknown): Promise<{ status: number; body: unknown }>;
  publishDeliveryRequest(): Promise<void>;
  refresh(): Promise<void>;
  inspect<T>(run: (client: PoolClient) => Promise<T>): Promise<T>;
  withAdmission<T>(
    run: (
      client: PoolClient,
      admission: Parameters<typeof readPublishedNotificationDeliveryRequest>[1],
    ) => Promise<T>,
  ): Promise<T>;
  setCallback(value: ((client: PoolClient) => Promise<void>) | undefined): void;
  assertKmsWithdrawalBlocked(): Promise<void>;
  assertWorkerWithdrawalBlocked(): Promise<void>;
  withdrawWorker(): Promise<void>;
  /** Existing fixture owner retains/restores exact bytes/mode; no business rows,
   * keys, cryptographic proofs or intermediate outcomes are reseeded. */
  withCiphertextFault(mode: 'missing' | 'corrupt', run: () => Promise<void>): Promise<void>;
}) {
  const source = input.source,
    p = input.preparation;
  expect(source.notificationOccurrenceId).toBe(p.occurrenceId);
  expect(source.worker.installationDigest).not.toBe(p.input.kmsInstallationDigest);
  const denied = { status: 200, body: { admitted: false, callbackRows: 0 } };
  const effectSnapshot = () =>
    input.inspect(async (client) => {
      const result: Record<string, unknown> = {};
      for (const table of [
        'evidence_kms_attempt',
        'evidence_kms_exchange',
        'evidence_wrapped_key',
        'notification_key_preparation',
        'notification_key_ciphertext',
        'notification_delivery',
        'notification_delivery_attempt',
        'notification_delivery_start',
        'outbox_event',
      ]) {
        const found = await client.query('select to_regclass($1)::text relation', [
          `control.${table}`,
        ]);
        if (!found.rows[0]?.relation) {
          result[table] = null;
          continue;
        }
        result[table] = (
          await client.query(
            `select to_jsonb(t) row from control.${table} t where participant_id=$1 and privacy_domain_id=$2 order by to_jsonb(t)::text`,
            [source.worker.participantId, source.worker.privacyDomainId],
          )
        ).rows;
      }
      return canonicalJson(result);
    });
  await expect(input.call(source, true)).rejects.toThrow();
  expect(
    await input.call({ ...source, worker: { ...source.worker, privacyDomainId: id() } }),
  ).toMatchObject({ status: 403 });
  expect(await input.call(source)).toMatchObject(denied); // Not yet PUBLISHED through its owner.
  await input.publishDeliveryRequest();
  await input.withAdmission(async (client, admission) => {
    await lockEvidenceLifecycle(client, source.worker.participantId, source.worker.privacyDomainId);
    const published = await readPublishedNotificationDeliveryRequest(client, admission, source);
    expect(published.claims.keyPreparationId).toBe(p.preparationId);
    expect(published.claims.payloadObjectId).toBe(p.objectIntent.payloadObjectId);
    expect(published.claims.payloadDigest).toBe(p.objectIntent.payloadDigest);
    expect(published.claims.sourceEventId).toBe(p.sourceEventId);
    expect(published.claims.sourceReceiptDigest).toBe(p.sourceReceiptDigest);
  });
  await input.refresh();
  const before = await effectSnapshot();
  expect(await input.call(source)).toMatchObject({
    status: 200,
    body: { admitted: true, payloadObjectId: p.objectIntent.payloadObjectId },
  });
  expect(await effectSnapshot()).toBe(before); // Includes unchanged original producer/request bytes and no new KMS exchange.
  const publisher = await input.callPublisher(source);
  expect(
    publisher.status === 403 ||
      (publisher.status === 200 && (publisher.body as { admitted?: boolean }).admitted === false),
  ).toBe(true);
  for (const patch of [
    { eventId: id() },
    { notificationOccurrenceId: id() },
    { keyPreparationId: p.preparationId },
    { preparation: p },
    { ready: true },
  ])
    expect(await input.call({ ...source, ...patch })).toMatchObject(denied);
  expect(await effectSnapshot()).toBe(before);
  let callbackCalls = 0;
  input.setCallback(async () => {
    callbackCalls++;
    throw new Error('PRIVATE_CANARY');
  });
  await input.refresh();
  const failureBefore = await effectSnapshot();
  expect(await input.call(source)).toMatchObject(denied);
  expect(callbackCalls).toBe(1);
  expect(await effectSnapshot()).toBe(failureBefore);
  callbackCalls = 0;
  input.setCallback(async () => {
    callbackCalls++;
    await new Promise((resolve) => setTimeout(resolve, 5100));
  });
  await input.refresh();
  const expiryBefore = await effectSnapshot();
  expect(await input.call(source)).toMatchObject(denied); // Mandatory final five-second STATUS check rolls back the marker.
  expect(callbackCalls).toBe(1); // An already-expired admission is not final-check coverage.
  expect(await effectSnapshot()).toBe(expiryBefore);
  for (const mode of ['missing', 'corrupt'] as const) {
    callbackCalls = 0;
    input.setCallback(async () => {
      callbackCalls++;
    });
    await input.refresh();
    const faultBefore = await effectSnapshot();
    await input.withCiphertextFault(mode, async () => {
      expect(await input.call(source)).toMatchObject(denied);
    });
    expect(callbackCalls).toBe(0);
    expect(await effectSnapshot()).toBe(faultBefore);
    input.setCallback(undefined);
    await input.refresh();
    expect(await input.call(source)).toMatchObject({ status: 200, body: { admitted: true } });
  }
  await input.refresh();
  let entered!: () => void, release!: () => void;
  const arrival = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  input.setCallback(async () => {
    entered();
    await held;
  });
  const pending = input.call(source);
  try {
    await Promise.race([
      arrival,
      pending.then(() => {
        throw new Error('Delivery gate did not enter callback');
      }),
    ]);
    await input.assertWorkerWithdrawalBlocked();
    await input.assertKmsWithdrawalBlocked();
  } finally {
    release();
  }
  expect(await pending).toMatchObject({ status: 200, body: { admitted: true } });
  input.setCallback(undefined);
  await input.withdrawWorker();
  expect(await input.call(source)).toMatchObject({ status: 403 });
}
