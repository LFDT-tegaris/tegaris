import {
  requireNotificationProducerGeneration,
  exerciseNotificationDeliveryProducer,
  createNotificationProducerSigners,
  type NotificationProducerJourneyInput,
} from './notification-delivery-outcome-cases.js';
import {
  createNotificationCompletionJourneyActor,
  exerciseNotificationCompletionJourney,
  type NotificationCompletionJourneyCase,
} from './notification-completion-disposition-cases.js';
import {
  exerciseNotificationDeliveryRuntimeCase,
  type NotificationDeliveryRuntimeCase,
} from './notification-delivery-runtime-cases.js';
import { installNotificationCompletionSqlBridge } from '../../../services/identity-service/src/domain/notification-completion-worker.js';
import {
  decodeNotificationClaim,
  signNotificationClaim,
} from '../../../packages/security-kernel/src/notification-gateway/codec.js';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, readFile, writeFile, rename, stat, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import type { TLSSocket } from 'node:tls';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import { withEvidenceKeyRecipient } from '../../../services/identity-service/src/domain/evidence-key-recipient.js';
import { installEvidenceExportProducer } from '../../../services/control-api/src/evidence/export-producer-installation.js';
import {
  installInitialEvidenceKms,
  withdrawEvidenceKmsInstallation,
} from '../../../services/control-api/src/evidence/kms-installation.js';
import {
  EvidenceKmsError,
  evidenceKmsUnwrapInput,
  parseEvidenceKms,
  type EvidenceKmsPrepareInput,
} from '../../../services/control-api/src/evidence/kms-contracts.js';
import {
  EvidenceKmsState,
  inspectEvidenceKmsPrepareRequest,
} from '../../../services/control-api/src/evidence/kms-state.js';
import {
  EvidenceKmsRuntime,
  EvidenceKmsHttpsTransport,
} from '../../../services/control-api/src/evidence/kms-runtime.js';
import {
  sealNotificationPayload,
  openNotificationPayload,
} from '../../../services/control-api/src/evidence/notification-payload-crypto.js';
import {
  openVaultDirectory,
  putVaultFile,
  readVaultFile,
} from '../../../services/control-api/src/evidence/immutable-vault.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import {
  notificationOccurrenceUrn,
  validateNotificationKeyPreparation,
} from '../../../services/control-api/src/evidence/notification-key-contracts.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { evidenceKmsProviderFixture } from './evidence-kms-provider-fixture.js';
import { controlDatabaseRecoveryFixture } from './control-database-recovery-fixture.js';
import { NotificationOccurrenceRuntime } from '../../../services/control-api/src/notifications/occurrence-runtime.js';
import {
  withNotificationDeliveryRequest,
  withNotificationDeliveryConfiguration,
} from '../../../services/control-api/src/notifications/delivery-admission.js';
import { synchronizeNotificationDeliveryBudget } from '../../../services/control-api/src/notifications/delivery-start-state.js';
import { notificationDeliverySourceSelector } from '../../../services/control-api/src/notifications/delivery-source.js';
import { assertNotificationDeliveryBudgetMissingGeneration } from './notification-delivery-start-cases.js';
import {
  prepareNotificationDelivery,
  readNotificationDeliveryPreparation,
} from '../../../services/control-api/src/notifications/delivery-start-preparation.js';
import { assertNotificationDeliveryPreparationMissingGeneration } from './notification-delivery-preparation-cases.js';
import {
  notificationDeliveryWorkerContextIdentity,
  type NotificationWorkerAdmission,
} from '../../../services/identity-service/src/domain/notification-worker.js';
import { NotificationOccurrenceError } from '../../../services/control-api/src/notifications/occurrence-contract.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import {
  assertNotificationOccurrenceCases,
  assertNotificationOccurrencePublicationCases,
  assertNotificationOccurrencePublicationRollback,
  assertNotificationOccurrenceExpiredStatus,
  assertNotificationOccurrenceAtomicState,
  prepareNotificationOccurrenceWorkers,
  decodeNotificationOccurrenceCaseResponse,
  type NotificationOccurrenceCasesInput,
  type NotificationOccurrenceCaseMethod,
  type NotificationOccurrenceCaseActor,
  type NotificationOccurrenceCaseResult,
} from './notification-occurrence-cases.js';
import { NotificationKeyCustody } from '../../../services/control-api/src/evidence/notification-key-custody.js';
import { NotificationPayloadReader } from '../../../services/control-api/src/evidence/notification-payload-reader.js';
import {
  installNotificationPayloadReadCaseRoute,
  assertNotificationPayloadReadCases,
  assertNotificationPayloadReadLifecycle,
  type NotificationPayloadReadCall,
} from './notification-payload-read-cases.js';
import { NotificationEndpointVerificationState } from '../../../services/control-api/src/notifications/endpoint-verification-state.js';
import { prepareEvidenceExportCompletion } from '../../../services/control-api/src/evidence/export-completion.js';
import { observeEvidenceExportCompletion } from '../../../services/control-api/src/evidence/export-completion-observation.js';
import { publishEvidenceExportCompletion } from '../../../services/control-api/src/evidence/export-completion-publication.js';
import {
  signEvidenceExportCompletion,
  evidenceKeyId,
} from '../../../packages/security-kernel/src/index.js';
import {
  mountNotificationPayloadReferenceProbe,
  assertNotificationPayloadReferenceCases,
  assertNotificationDeliveryPayloadReferenceCases,
} from './notification-payload-reference-cases.js';
import {
  installNotificationKeyCustodyCaseRoutes,
  assertNotificationKeyCustodyCases,
  assertNotificationKeyRetainedReadback,
  prepareNotificationKeyExports,
  prepareNotificationKeyRouting,
} from './notification-key-custody-cases.js';

import { withdrawNotificationWorker } from '../../../services/control-api/src/notifications/worker-installation.js';
import { notificationKeyFile } from '../../../services/control-api/src/evidence/notification-key-contracts.js';

import {
  createNotificationReceiptProviderFixture,
  assertNotificationReceiptSignerInstallationCases,
  notificationFixtureSpki,
} from './notification-receipt-provider-fixture.js';
import {
  validateNotificationWorkerInstallation,
  NotificationWorkerAdmissionError,
} from '../../../services/control-api/src/notifications/worker-installation-contract.js';
import {
  notificationReceiptSigningPurpose,
  type NotificationReceiptSignerInstallation,
} from '../../../services/control-api/src/notifications/receipt-signer-installation.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
// SECRET-012 / SECRET-015 / SECRET-016 prerequisite: real internal Identity,
// PostgreSQL and TLS; only the external KMS is a fixture. The ciphertext uses the
// existing codec/immutable file owner and joins genuine governed exports and
// notification custody and real atomic occurrence publication below. Delivery
// and production HSM/escrow remain separate. This test requires an
// exclusively owned disposable recovery database: the original is fenced once.
integration(
  'fences Evidence key preparation by real TLS and distinct immutable KMS installation',
  async () => {
    if (
      !process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL ||
      !process.env.OPENPC_TEST_TMP_ROOT
    )
      throw new Error(
        'BLOCKED: Evidence KMS acceptance requires the isolated Control recovery inputs',
      );
    let admin = new Pool({ connectionString: adminUrl, max: 2 });
    let runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    let installer = new Pool({
      connectionString: adminUrl,
      options: '-c role=openpc_control_owner',
      max: 1,
    });
    const scope = { participantId: id(), privacyDomainId: id() };
    const principalId = id(),
      credentialId = id(),
      workloadId = id();
    const san = `urn:openpc:participant:${scope.participantId}:workload:${workloadId}`;
    const tls = await runtimeSnapshotTlsFixture(san);
    const rogue = await runtimeSnapshotTlsFixture(san);
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let app: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
    let provider: Awaited<ReturnType<typeof evidenceKmsProviderFixture>> | undefined;
    let notificationSetup: Awaited<ReturnType<typeof prepareNotificationKeyRouting>> | undefined;
    const occurrenceTls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>[] = [];
    let occurrenceWorkers:
      Awaited<ReturnType<typeof prepareNotificationOccurrenceWorkers>> | undefined;
    let occurrenceOriginal:
      Awaited<ReturnType<typeof assertNotificationOccurrenceCases>> | undefined;
    let occurrenceRollbackFailure: unknown;
    let lostOccurrenceReply = false;
    let configurationAdmissions = 0;
    let budgetDenialFailure: unknown;
    let preparationDenialFailure: unknown;
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'evidence-kms-'));
    let passed = false;
    let poolsClosed = false;
    let firstFailure: unknown;
    const completionFailures: unknown[] = [];
    const completionKeyAttempts: string[] = [];
    let completionKeyEffects = 0;
    try {
      for (let index = 0; index < 2; index++) {
        occurrenceTls.push(
          await runtimeSnapshotTlsFixture(
            `urn:openpc:participant:${scope.participantId}:workload:${id()}`,
          ),
        );
      }
      for (const table of [
        'evidence_kms_attempt',
        'evidence_kms_exchange',
        'evidence_wrapped_key',
      ]) {
        const referencedOwner =
          table === 'evidence_kms_attempt' || table === 'evidence_wrapped_key';
        const referencedColumn = table === 'evidence_wrapped_key' ? 'key_id' : 'attempt_id';
        const privilege = (
          await admin.query(
            `select has_table_privilege('openpc_control_owner',$1,'TRIGGER') as ddl,
           (select relforcerowsecurity from pg_class where oid=to_regclass($1)) as forced_rls,
           has_table_privilege('openpc_control_owner',$1,'INSERT') as owner_write,
           has_table_privilege('openpc_control_owner',$1,'SELECT') as owner_read,
           has_table_privilege('openpc_control_owner',$1,'UPDATE') as owner_table_update,
           has_column_privilege('openpc_control_owner',$1,$2,'UPDATE') as owner_key_lock,
           has_column_privilege('openpc_control_owner',$1,'attempt_id','UPDATE') as owner_attempt_lock,
           has_column_privilege('openpc_control_owner',$1,'participant_id','UPDATE') as owner_scope_update,
           has_table_privilege('openpc_control_owner',$1,'REFERENCES') as owner_table_references,
           has_column_privilege('openpc_control_owner',$1,'participant_id','REFERENCES') as owner_participant_references,
           has_column_privilege('openpc_control_owner',$1,'privacy_domain_id','REFERENCES') as owner_privacy_references,
           has_column_privilege('openpc_control_owner',$1,$2,'REFERENCES') as owner_key_references,
           has_table_privilege('openpc_control_runtime',$1,'INSERT') as runtime_write`,
            [`control.${table}`, referencedColumn],
          )
        ).rows[0];
        expect(privilege).toEqual({
          ddl: false,
          forced_rls: true,
          owner_write: false,
          owner_read: referencedOwner,
          owner_table_update: false,
          owner_key_lock: referencedOwner,
          owner_attempt_lock: table === 'evidence_kms_attempt',
          owner_scope_update: false,
          owner_table_references: false,
          owner_participant_references: false,
          owner_privacy_references: false,
          owner_key_references: false,
          runtime_write: true,
        });
      }
      const recovery = await controlDatabaseRecoveryFixture('evidence-remote-restore.dump', root);
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        scope.participantId,
        scope.privacyDomainId,
        {
          notificationEndpointOwners: (pool, verifier) =>
            new NotificationEndpointVerificationState(pool, verifier),
        },
      );
      const tlsKey = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Evidence KMS initial workload trust','ACTIVE',1)`,
        [principalId, scope.participantId],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','evidence-kms-test-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          credentialId,
          scope.participantId,
          principalId,
          san,
          `urn:openpc:workload:${workloadId}`,
          Buffer.from(sha256(tlsKey).slice(7), 'hex'),
          tlsKey,
          Buffer.from(sha256(tls.parsed.raw).slice(7), 'hex'),
          new Date(tls.parsed.validFrom),
          new Date(tls.parsed.validTo),
        ],
      );
      const now = Date.now();
      const exportSigner = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const exportSpki = exportSigner.publicKey.export({ type: 'spki', format: 'der' });
      const producerTrustDigest = await installEvidenceExportProducer(installer, {
        owner: 'LS-EVIDENCE-EXPORT',
        purpose: 'pc.cose.evidence-export-completion-receipt.v1',
        environmentId: 'local-kms',
        ...scope,
        sourceId: id(),
        principalId,
        workloadCredentialId: credentialId,
        workloadEpoch: '1',
        workloadId: `urn:openpc:workload:${workloadId}`,
        secretClass: 'SECRET-SIGNING-KEY',
        secretReference: 'secret://test-kms/producer-signing#v1',
        secretVersion: 'v1',
        publicKeySpkiHex: exportSpki.toString('hex'),
        keyEpoch: '1',
        validFromNs: String(BigInt(now - 1000) * 1000000n),
        validUntilNs: String(BigInt(now + 300000) * 1000000n),
        installationReference: 'kms-initial-producer',
      });
      provider = await evidenceKmsProviderFixture(tls, {
        ...scope,
        environmentId: 'local-kms',
        producerTrustDigest,
      });
      const pins = provider.pins;
      const wrongPin = new EvidenceKmsHttpsTransport(
        { ...pins, providerTlsSpkiDigest: `sha256:${'f'.repeat(64)}` },
        { ca: tls.server.ca, certificate: tls.certificate, privateKey: tls.privateKey },
      );
      try {
        await expect(
          wrongPin.exchange(Buffer.from('{}'), new AbortController().signal),
        ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
      } finally {
        wrongPin.close();
      }
      expect(provider.counters()).toMatchObject({
        prepareCalls: 0,
        prepareEffects: 0,
        unwrapCalls: 0,
      });
      const installationDigest = await installInitialEvidenceKms(installer, pins);
      expect(await installInitialEvidenceKms(installer, pins)).toBe(installationDigest);
      await expect(
        installInitialEvidenceKms(runtime, { ...pins, installationId: id() }),
      ).rejects.toThrow();
      await expect(
        installInitialEvidenceKms(installer, { ...pins, providerKeyVersion: 'v2' }),
      ).rejects.toThrow();
      const recipient = { ...scope, producerTrustDigest, installationDigest };
      let kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
      let state = new EvidenceKmsState(runtime, kernel);
      let borrowed: Buffer | undefined;
      let leaseSignal: AbortSignal | undefined;
      let persistenceFault: 'BEFORE_WRITE' | 'AFTER_WRITE' | 'LOST_ACK' | undefined;
      const plaintext = Buffer.from('MINIMIZED_PAYLOAD_CANARY');
      const vaultDirectory = await openVaultDirectory(root);
      let referenceCallback: ((client: PoolClient) => Promise<void>) | undefined;
      let deliveryReferenceAdmissionProbe:
        ((client: PoolClient, admission: NotificationWorkerAdmission) => Promise<void>) | undefined;
      const inspectOccurrence: NotificationOccurrenceCasesInput['inspect'] = (run) =>
        runScopedTransaction(
          runtime,
          { ...scope, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
          id,
          async (client) => {
            await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
            return run(client);
          },
        );
      // Callbacks run only inside this existing real TLS server request. Tokens
      // select test work; the invoked product owner still authenticates the peer.
      const joinedPeers = new Map<string, (socket: TLSSocket) => Promise<void>>();
      const build = () => {
        const kms = new EvidenceKmsRuntime(runtime, kernel, {
          ca: tls.server.ca,
          certificate: tls.certificate,
          privateKey: tls.privateKey,
        });
        const server = buildLocalWorkloadMtlsService(runtime, kernel, {
          ...tls.server,
          ca: Buffer.concat([tls.server.ca, ...occurrenceTls.map((peer) => peer.server.ca)]),
        });
        const occurrence = new NotificationOccurrenceRuntime(runtime, kernel, vaultDirectory);
        server.post('/test/notification-joined-peer', async (request, reply) => {
          const body = request.body as { token?: unknown };
          if (!body || Object.keys(body).join(',') !== 'token' || typeof body.token !== 'string')
            return reply.code(400).send({ code: 'INVALID' });
          const run = joinedPeers.get(body.token);
          if (!run) return reply.code(400).send({ code: 'INVALID' });
          joinedPeers.delete(body.token);
          await run(request.raw.socket as TLSSocket);
          return { completed: true };
        });
        for (const command of [
          'prepare',
          'readOriginal',
          'dispatch',
          'markUnknown',
          'observe',
          'publish',
          'readPublication',
        ] as const)
          server.post(`/test/notification-occurrence/${command}`, async (request, reply) => {
            try {
              const result = await occurrence[command](
                request.raw.socket as TLSSocket,
                request.body,
              );
              if ('preparation' in result)
                return {
                  preparation: result.preparation,
                  state: result.state,
                  coseHex: result.cose?.toString('hex') ?? null,
                };
              return result;
            } catch (error) {
              return reply.code(403).send({
                code: error instanceof NotificationOccurrenceError ? error.code : 'UNAVAILABLE',
              });
            }
          });
        server.post('/test/notification-occurrence/publish-lost-ack', async (request, reply) => {
          try {
            const result = await occurrence.publish(request.raw.socket as TLSSocket, request.body);
            expect(result.state).toBe('PUBLISHED');
            lostOccurrenceReply = true;
            request.raw.socket.destroy();
            return reply;
          } catch (error) {
            return reply.code(403).send({
              code: error instanceof NotificationOccurrenceError ? error.code : 'UNAVAILABLE',
            });
          }
        });
        server.post('/test/notification-occurrence/rollback', async (request, reply) => {
          try {
            if (!occurrenceOriginal) throw new Error('Missing original occurrence pair');
            await assertNotificationOccurrencePublicationRollback({
              pool: runtime,
              kernel,
              vaultDirectory,
              socket: request.raw.socket as TLSSocket,
              original: occurrenceOriginal,
              inspect: inspectOccurrence,
            });
            return { rolledBack: true };
          } catch (error) {
            occurrenceRollbackFailure = error;
            return reply.code(403).send({ code: 'OCCURRENCE_ROLLBACK_FAILED' });
          }
        });
        server.post('/test/notification-delivery/source', async (request, reply) => {
          try {
            const selector = notificationDeliverySourceSelector.parse(request.body);
            let retainedContext: (() => unknown) | undefined;
            const result = await withNotificationDeliveryRequest(
              runtime,
              kernel,
              request.raw.socket as TLSSocket,
              selector,
              async (client, admission, source) => {
                const contextIdentity = notificationDeliveryWorkerContextIdentity(
                  admission,
                  client,
                  selector.worker,
                );
                expect(contextIdentity.authorizationContextId).toBe(
                  admission.installation.profile.workloadCredentialId,
                );
                expect(contextIdentity.authorizationContextEpoch).toBe(
                  Number(admission.installation.profile.workloadEpoch),
                );
                expect(contextIdentity.authorizationDigest).toBe(admission.authorityDigest);
                expect(contextIdentity.accessClassIds).toEqual(['ACCESS-NOTIFICATION']);
                expect(() =>
                  notificationDeliveryWorkerContextIdentity(
                    { ...admission },
                    client,
                    selector.worker,
                  ),
                ).toThrow();
                expect(() =>
                  notificationDeliveryWorkerContextIdentity(
                    admission,
                    Object.create(client) as PoolClient,
                    selector.worker,
                  ),
                ).toThrow();
                expect(() =>
                  notificationDeliveryWorkerContextIdentity(admission, client, {
                    ...selector.worker,
                    privacyDomainId: id(),
                  }),
                ).toThrow();
                retainedContext = () =>
                  notificationDeliveryWorkerContextIdentity(admission, client, selector.worker);
                await deliveryReferenceAdmissionProbe?.(client, admission);
                return {
                  claims: source.claims,
                  sourceOperationId: source.sourceOperationId,
                  sourceReceiptDigest: source.sourceReceiptDigest,
                };
              },
            );
            expect(retainedContext).toBeDefined();
            expect(retainedContext!).toThrow();
            return result;
          } catch {
            return reply.code(403).send({ code: 'UNAVAILABLE' });
          }
        });
        server.post('/test/notification-delivery/configuration', async (request, reply) => {
          try {
            return await withNotificationDeliveryConfiguration(
              runtime,
              kernel,
              request.raw.socket as TLSSocket,
              request.body,
              async () => {
                configurationAdmissions++;
                return { admitted: true };
              },
            );
          } catch {
            return reply.code(403).send({ code: 'UNAVAILABLE' });
          }
        });
        server.post('/test/notification-delivery/budget-unready', async (request, reply) => {
          try {
            const source = notificationDeliverySourceSelector.parse(request.body);
            const socket = request.raw.socket as TLSSocket;
            await assertNotificationDeliveryBudgetMissingGeneration({
              source,
              call: (value) =>
                synchronizeNotificationDeliveryBudget(runtime, kernel, socket, value),
              inspect: inspectOccurrence,
              withSource: (run) =>
                withNotificationDeliveryRequest(
                  runtime,
                  kernel,
                  socket,
                  source,
                  (client, _admission, published) => run(client, published),
                ),
              restart: async () => {
                throw new Error('Missing-generation denial needs no restart');
              },
            });
            return { unchanged: true };
          } catch (error) {
            budgetDenialFailure = error;
            return reply.code(403).send({ code: 'BUDGET_DENIAL_FAILED' });
          }
        });
        server.post('/test/notification-delivery/preparation-unready', async (request, reply) => {
          try {
            const source = notificationDeliverySourceSelector.parse(request.body);
            const socket = request.raw.socket as TLSSocket;
            await assertNotificationDeliveryPreparationMissingGeneration({
              source,
              prepare: (value) => prepareNotificationDelivery(runtime, kernel, socket, value),
              read: (value) => readNotificationDeliveryPreparation(runtime, kernel, socket, value),
              inspect: inspectOccurrence,
              withSource: (run) =>
                withNotificationDeliveryRequest(
                  runtime,
                  kernel,
                  socket,
                  source,
                  (client, _admission, published) => run(client, published),
                ),
              providerCalls: async () =>
                Object.values(provider!.counters()).reduce((sum, n) => sum + n, 0),
            });
            return { unchanged: true };
          } catch (error) {
            preparationDenialFailure = error;
            return reply.code(403).send({ code: 'PREPARATION_DENIAL_FAILED' });
          }
        });
        mountNotificationPayloadReferenceProbe(server, {
          pool: runtime,
          kernel,
          vaultDirectory,
          callback: (client) => referenceCallback?.(client) ?? Promise.resolve(),
        });
        installNotificationKeyCustodyCaseRoutes(
          server,
          new NotificationKeyCustody(
            runtime,
            kernel,
            {
              ca: tls.server.ca,
              certificate: tls.certificate,
              privateKey: tls.privateKey,
            },
            vaultDirectory,
          ),
        );
        installNotificationPayloadReadCaseRoute(
          server,
          new NotificationPayloadReader(
            runtime,
            kernel,
            {
              ca: tls.server.ca,
              certificate: tls.certificate,
              privateKey: tls.privateKey,
            },
            vaultDirectory,
          ),
        );
        server.post('/test/notification-key/source', async (request, reply) => {
          try {
            const original = await prepareEvidenceExportCompletion(
              runtime,
              kernel,
              request.raw.socket as TLSSocket,
              request.body,
            );
            return { state: original.state, eventId: original.claims.eventId };
          } catch {
            return reply.code(403).send({ code: 'EXPORT_COMPLETION_UNAVAILABLE' });
          }
        });
        server.post('/test/notification-key/source-publish', async (request, reply) => {
          try {
            const socket = request.raw.socket as TLSSocket;
            const original = await prepareEvidenceExportCompletion(
              runtime,
              kernel,
              socket,
              request.body,
            );
            const privateKey = exportSigner.privateKey.export({ type: 'pkcs8', format: 'der' });
            let cose: Buffer;
            try {
              cose = signEvidenceExportCompletion(original.claims, privateKey, exportSpki);
            } finally {
              privateKey.fill(0);
            }
            await observeEvidenceExportCompletion(runtime, kernel, socket, {
              ...(request.body as Record<string, unknown>),
              coseHex: cose.toString('hex'),
            });
            const published = await publishEvidenceExportCompletion(
              runtime,
              kernel,
              socket,
              request.body,
            );
            return { state: published.state };
          } catch {
            return reply.code(403).send({ code: 'EXPORT_COMPLETION_UNAVAILABLE' });
          }
        });
        for (const command of ['prepareObjectKey', 'readAttempt', 'observeCurrentStatus'] as const)
          server.post(`/test/evidence-kms/${command}`, async (request, reply) => {
            try {
              return await kms[command](
                request.raw.socket as TLSSocket,
                request.body,
                new AbortController().signal,
              );
            } catch (error) {
              return reply.code(403).send({
                code: error instanceof EvidenceKmsError ? error.message : 'OPS_SECRET_UNRESOLVED',
              });
            }
          });
        server.post('/test/evidence-kms/seal', async (request, reply) => {
          try {
            const parsed = parseEvidenceKms(evidenceKmsUnwrapInput, request.body);
            const original = await state.readOriginal(request.raw.socket as TLSSocket, {
              recipient: parsed.recipient,
              attemptId: parsed.attemptId,
            });
            const intent = inspectEvidenceKmsPrepareRequest(original.requestBytes).objectIntent;
            const fault = persistenceFault;
            persistenceFault = undefined;
            const sealed = await kms.withObjectKey(
              request.raw.socket as TLSSocket,
              request.body,
              new AbortController().signal,
              (material) => {
                borrowed = material.bytes;
                leaseSignal = material.signal;
                return sealNotificationPayload(
                  { ...intent, keyId: material.keyId },
                  plaintext,
                  material,
                );
              },
              async (client, ciphertext) => {
                expect(borrowed?.every((byte) => byte === 0)).toBe(true);
                expect(leaseSignal?.aborted).toBe(true);
                const name = `${ciphertext.payloadObjectId}.${ciphertext.attemptId}.raw`;
                // The existing immutable owner receives ciphertext only, before
                // receipt commit. A write survives a later SQL/ACK failure.
                await putVaultFile(
                  fault === 'BEFORE_WRITE' ? join(vaultDirectory, 'missing') : vaultDirectory,
                  name,
                  ciphertext.bytes,
                );
                const readback = await readVaultFile(vaultDirectory, name, 131072);
                if (fault === 'AFTER_WRITE') await client.query('select 1/0');
                return readback;
              },
            );
            if (fault === 'LOST_ACK') {
              request.raw.socket.destroy();
              return reply;
            }
            return { encryptedObjectDigest: sealed.encryptedObjectDigest };
          } catch (error) {
            return reply.code(403).send({
              code: error instanceof EvidenceKmsError ? error.message : 'OPS_SECRET_UNRESOLVED',
            });
          }
        });
        server.post('/test/evidence-kms/open', async (request, reply) => {
          try {
            const parsed = parseEvidenceKms(evidenceKmsUnwrapInput, request.body);
            const original = await state.readOriginal(request.raw.socket as TLSSocket, {
              recipient: parsed.recipient,
              attemptId: parsed.attemptId,
            });
            const intent = inspectEvidenceKmsPrepareRequest(original.requestBytes).objectIntent;
            const bytes = await readVaultFile(
              vaultDirectory,
              `${intent.payloadObjectId}.${parsed.attemptId}.raw`,
              131072,
            );
            return await kms.withObjectKey(
              request.raw.socket as TLSSocket,
              request.body,
              new AbortController().signal,
              (material) => {
                borrowed = material.bytes;
                const opened = openNotificationPayload(
                  bytes,
                  sha256(bytes),
                  { ...intent, keyId: material.keyId },
                  material,
                );
                try {
                  return { payloadDigest: sha256(opened), encryptedObjectDigest: sha256(bytes) };
                } finally {
                  opened.fill(0);
                }
              },
            );
          } catch (error) {
            return reply.code(403).send({
              code: error instanceof EvidenceKmsError ? error.message : 'OPS_SECRET_UNRESOLVED',
            });
          }
        });
        server.post('/test/evidence-kms/admit', async (request, reply) => {
          try {
            return await withEvidenceKeyRecipient(
              runtime,
              kernel,
              request.raw.socket as TLSSocket,
              request.body,
              'ENCRYPT',
              async (_client, admission) => ({ installationDigest: admission.installation.digest }),
            );
          } catch {
            return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
          }
        });
        for (const command of ['prepare', 'readOriginal', 'dispatch', 'unknown'] as const)
          server.post(`/test/evidence-kms/${command}`, async (request, reply) => {
            try {
              const result = await state[command](request.raw.socket as TLSSocket, request.body);
              return {
                attemptId: result.attemptId,
                requestDigest: result.requestDigest,
                state: result.state,
              };
            } catch (error) {
              return reply.code(403).send({
                code: error instanceof EvidenceKmsError ? error.message : 'OPS_SECRET_UNRESOLVED',
              });
            }
          });
        return server;
      };
      app = build();
      let address = await app.listen({ host: '127.0.0.1', port: 0 });
      const call = (command: string, body: unknown) =>
        tls.post(`${address}/test/evidence-kms/${command}`, body);
      expect(await call('admit', recipient)).toMatchObject({
        status: 200,
        body: { installationDigest },
      });
      await expect(
        tls.post(`${address}/test/evidence-kms/admit`, recipient, null),
      ).rejects.toThrow();
      await expect(
        tls.post(`${address}/test/evidence-kms/admit`, recipient, rogue),
      ).rejects.toThrow();
      for (const change of [
        { privacyDomainId: id() },
        { participantId: id() },
        { producerTrustDigest: sha256('different-producer') },
        { installationDigest: sha256('different-grant') },
        { admitted: true },
        { purpose: 'POSTGRES_CONNECT' },
      ])
        expect(await call('admit', { ...recipient, ...change })).toMatchObject({ status: 403 });
      const request = {
        recipient,
        attemptId: id(),
        objectIntent: {
          ...scope,
          environmentId: 'local-kms',
          payloadObjectId: id(),
          objectVersion: '1',
          notificationOccurrenceRef: `urn:openpc:notification-occurrence:${id()}`,
          routingProfileDigest: sha256('routing'),
          templateDigest: sha256('template'),
          recipientSetDigest: sha256('recipients'),
          redactionProfileDigest: sha256('redaction'),
          preferenceGeneration: '1',
          payloadDigest: sha256('minimized payload'),
        },
      };
      // No Notification business occurrence or provider result is seeded here.
      // Object-intent metadata exercises key preparation only, not delivery/custody.
      const prepared = await call('prepare', request);
      expect(prepared).toMatchObject({
        status: 200,
        body: { state: 'PREPARED', attemptId: request.attemptId },
      });
      // RI checks need the referenced owner's row-lock privilege. Direct owner
      // reads/updates still cannot cross forced RLS or act as a runtime principal.
      expect(
        (await installer.query('select attempt_id from control.evidence_kms_attempt')).rows,
      ).toEqual([]);
      expect(
        (
          await installer.query(
            'update control.evidence_kms_attempt set attempt_id=attempt_id returning attempt_id',
          )
        ).rows,
      ).toEqual([]);
      expect(await call('prepare', request)).toEqual(prepared);
      expect(await call('prepare', { ...request, attemptId: id() })).toMatchObject({ status: 403 });
      const selector = { recipient, attemptId: request.attemptId };
      const before = await admin.query<{ request_bytes: Buffer }>(
        `select request_bytes from control.evidence_kms_attempt
      where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        [scope.participantId, scope.privacyDomainId, request.attemptId],
      );
      expect(await call('dispatch', selector)).toMatchObject({
        status: 200,
        body: { state: 'DISPATCHED' },
      });
      expect(await call('unknown', selector)).toMatchObject({
        status: 200,
        body: { state: 'UNKNOWN' },
      });
      expect(await call('dispatch', selector)).toMatchObject({ status: 403 });
      await app.close();
      app = build();
      address = await app.listen({ host: '127.0.0.1', port: 0 });
      expect(await call('readOriginal', selector)).toMatchObject({
        status: 200,
        body: { state: 'UNKNOWN' },
      });
      const after = await admin.query<{ request_bytes: Buffer }>(
        `select request_bytes from control.evidence_kms_attempt
      where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        [scope.participantId, scope.privacyDomainId, request.attemptId],
      );
      expect(after.rows[0]!.request_bytes).toEqual(before.rows[0]!.request_bytes);
      const payloadCase: EvidenceKmsPrepareInput = {
        recipient,
        attemptId: id(),
        objectIntent: {
          ...request.objectIntent,
          objectVersion: '1',
          payloadObjectId: id(),
          notificationOccurrenceRef: `urn:openpc:notification-occurrence:${id()}`,
          payloadDigest: sha256(plaintext),
        },
      };
      provider.loseNextResponse('PREPARE');
      expect(await call('prepareObjectKey', payloadCase)).toMatchObject({ status: 403 });
      expect(provider.counters()).toMatchObject({ prepareCalls: 1, prepareEffects: 1 });
      const recovered = await call('prepareObjectKey', payloadCase);
      expect(recovered.status).toBe(200);
      const keyId = (recovered.body as { keyId: string }).keyId;
      expect(keyId).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(provider.counters()).toMatchObject({ prepareCalls: 1, prepareEffects: 1 });
      const originalRecord = await admin.query<{ record_bytes: Buffer; record_cose: Buffer }>(
        `select record_bytes,record_cose
        from control.evidence_wrapped_key where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        [scope.participantId, scope.privacyDomainId, payloadCase.attemptId],
      );
      expect(originalRecord.rowCount).toBe(1);
      // The populated wrapped record needs SELECT/UPDATE(key_id) only for FK
      // row locking. Neither unscoped nor matching scoped owner access acquires
      // a runtime policy. Both direct attempts must see/change zero rows.
      expect(
        (await installer.query('select key_id from control.evidence_wrapped_key')).rows,
      ).toEqual([]);
      const ownerUpdate = await installer.query(
        'update control.evidence_wrapped_key set key_id=key_id returning key_id',
      );
      expect(ownerUpdate.rowCount).toBe(0);
      expect(ownerUpdate.rows).toEqual([]);
      await runScopedTransaction(
        installer,
        { ...scope, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
        id,
        async (client) => {
          expect(
            (
              await client.query(
                'select key_id from control.evidence_wrapped_key where key_id=$1',
                [keyId],
              )
            ).rows,
          ).toEqual([]);
          const scopedUpdate = await client.query(
            'update control.evidence_wrapped_key set key_id=key_id where key_id=$1 returning key_id',
            [keyId],
          );
          expect(scopedUpdate.rowCount).toBe(0);
          expect(scopedUpdate.rows).toEqual([]);
        },
      );
      expect(
        (
          await admin.query<{ record_bytes: Buffer; record_cose: Buffer }>(
            `select record_bytes,record_cose from control.evidence_wrapped_key
         where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and key_id=$4`,
            [scope.participantId, scope.privacyDomainId, payloadCase.attemptId, keyId],
          )
        ).rows,
      ).toEqual(originalRecord.rows);
      const keyRequest = { recipient, attemptId: payloadCase.attemptId, keyId, use: 'ENCRYPT' };
      for (const fault of ['STALE', 'WRONG_NONCE', 'RECOVERY_WRONG_SIGNER'] as const) {
        provider.nextFault(fault);
        expect(
          await call('readAttempt', { recipient, attemptId: payloadCase.attemptId }),
        ).toMatchObject({ status: 403 });
      }
      expect(
        await call('readAttempt', { recipient, attemptId: payloadCase.attemptId }),
      ).toMatchObject({ status: 200, body: { keyId } });
      const beforeWrongKey = provider.counters().unwrapCalls;
      expect(await call('seal', { ...keyRequest, keyId: sha256('wrong-key') })).toMatchObject({
        status: 403,
      });
      expect(provider.counters().unwrapCalls).toBe(beforeWrongKey);
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.evidence_kms_exchange
        where participant_id=$1 and attempt_id=$2 and kind='UNWRAP'`,
            [scope.participantId, payloadCase.attemptId],
          )
        ).rows[0].count,
      ).toBe(0);
      expect(await call('seal', keyRequest)).toMatchObject({ status: 200 });
      expect(borrowed?.every((byte) => byte === 0)).toBe(true);
      const originalName = `${payloadCase.objectIntent.payloadObjectId}.${payloadCase.attemptId}.raw`;
      const sealedOriginal = await readVaultFile(vaultDirectory, originalName, 131072);
      const unwrapCount = provider.counters().unwrapCalls;
      expect(await call('seal', keyRequest)).toMatchObject({ status: 403 });
      expect(provider.counters().unwrapCalls).toBe(unwrapCount);
      await app.close();
      app = build();
      address = await app.listen({ host: '127.0.0.1', port: 0 });
      expect(await call('open', { ...keyRequest, use: 'DECRYPT' })).toMatchObject({
        status: 200,
        body: { payloadDigest: sha256(plaintext) },
      });
      expect(borrowed?.every((byte) => byte === 0)).toBe(true);
      expect(await readVaultFile(vaultDirectory, originalName, 131072)).toEqual(sealedOriginal);
      provider.loseNextResponse('UNWRAP');
      expect(await call('open', { ...keyRequest, use: 'DECRYPT' })).toMatchObject({ status: 403 });
      const lostUnwrapCount = provider.counters().unwrapCalls;
      expect(await call('open', { ...keyRequest, use: 'DECRYPT' })).toMatchObject({ status: 403 });
      expect(provider.counters().unwrapCalls).toBe(lostUnwrapCount);
      expect(
        await call('readAttempt', { recipient, attemptId: payloadCase.attemptId }),
      ).toMatchObject({ status: 200, body: { keyId } });
      expect(await call('open', { ...keyRequest, use: 'DECRYPT' })).toMatchObject({ status: 200 });
      for (const fault of ['BEFORE_WRITE', 'AFTER_WRITE', 'LOST_ACK'] as const) {
        const independent: EvidenceKmsPrepareInput = {
          ...payloadCase,
          attemptId: id(),
          objectIntent: {
            ...payloadCase.objectIntent,
            payloadObjectId: id(),
            notificationOccurrenceRef: `urn:openpc:notification-occurrence:${id()}`,
          },
        };
        const prepared = await call('prepareObjectKey', independent);
        expect(prepared.status).toBe(200);
        const faultKeyId = (prepared.body as { keyId: string }).keyId;
        const faultKey = {
          recipient,
          attemptId: independent.attemptId,
          keyId: faultKeyId,
          use: 'ENCRYPT',
        };
        persistenceFault = fault;
        if (fault === 'LOST_ACK') await expect(call('seal', faultKey)).rejects.toThrow();
        else expect(await call('seal', faultKey)).toMatchObject({ status: 403 });
        expect(borrowed?.every((byte) => byte === 0)).toBe(true);
        expect(leaseSignal?.aborted).toBe(true);
        const originalExchange = (
          await admin.query(
            `select state,receipt_bytes,request_bytes from control.evidence_kms_exchange
          where participant_id=$1 and attempt_id=$2 and kind='UNWRAP'`,
            [scope.participantId, independent.attemptId],
          )
        ).rows;
        expect(originalExchange).toHaveLength(1);
        expect(originalExchange[0].state).toBe(fault === 'LOST_ACK' ? 'PROVED' : 'UNKNOWN');
        if (fault !== 'LOST_ACK') expect(originalExchange[0].receipt_bytes).toBeNull();
        const name = `${independent.objectIntent.payloadObjectId}.${independent.attemptId}.raw`;
        let persisted: Buffer | undefined;
        if (fault === 'BEFORE_WRITE')
          await expect(readVaultFile(vaultDirectory, name, 131072)).rejects.toThrow();
        else persisted = await readVaultFile(vaultDirectory, name, 131072);
        const calls = provider.counters().unwrapCalls;
        await app.close();
        app = build();
        address = await app.listen({ host: '127.0.0.1', port: 0 });
        expect(
          await call('readAttempt', { recipient, attemptId: independent.attemptId }),
        ).toMatchObject({ status: 200, body: { keyId: faultKeyId } });
        // Even proof that the external unwrap succeeded cannot recreate lost
        // ciphertext. The only usable recovery is the original persisted object.
        expect(await call('seal', faultKey)).toMatchObject({ status: 403 });
        expect(provider.counters().unwrapCalls).toBe(calls);
        if (fault === 'BEFORE_WRITE') {
          expect(await call('open', { ...faultKey, use: 'DECRYPT' })).toMatchObject({
            status: 403,
          });
          expect(provider.counters().unwrapCalls).toBe(calls);
        } else {
          expect(await call('open', { ...faultKey, use: 'DECRYPT' })).toMatchObject({
            status: 200,
            body: { payloadDigest: sha256(plaintext), encryptedObjectDigest: sha256(persisted!) },
          });
          expect(await readVaultFile(vaultDirectory, name, 131072)).toEqual(persisted);
        }
        expect(
          (
            await admin.query(
              `select request_bytes from control.evidence_kms_exchange
          where participant_id=$1 and attempt_id=$2 and kind='UNWRAP'
          and convert_from(request_bytes,'UTF8')::jsonb->>'keyUse'='ENCRYPT'`,
              [scope.participantId, independent.attemptId],
            )
          ).rows.map((row) => row.request_bytes),
        ).toEqual([originalExchange[0].request_bytes]);
      }
      // Join the real notification owner only after the accepted KMS fault
      // corpus. Its prerequisites use the same governed scope and external KMS.
      expect(provider.counters().prepareEffects).toBe(4);
      const sourceScope = { ...scope, streamId: 'notification-custody-authentication' };
      const worker = new Pool({
        connectionString: process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL,
        max: 1,
      });
      let exports: string[];
      try {
        exports = await prepareNotificationKeyExports({
          fixture,
          worker,
          scope: sourceScope,
          root,
          prepareCompletion: (evidenceExportId) =>
            tls.post(`${address}/test/notification-key/source`, {
              ...sourceScope,
              trustDigest: producerTrustDigest,
              evidenceExportId,
            }),
        });
      } finally {
        await worker.end();
      }
      notificationSetup = await prepareNotificationKeyRouting({
        admin,
        installer,
        runtimeUrl: runtimeUrl!,
        fixture,
        peer: tls,
        principalId,
        credentialId,
        workloadId,
        pins,
        root,
      });
      const custodyInput = (evidenceExportId: string) => ({
        scope: sourceScope,
        evidenceExportId,
        producerTrustDigest,
        kmsInstallationDigest: installationDigest,
        routing: notificationSetup!.routing,
      });
      const custodyCall: Parameters<typeof assertNotificationKeyCustodyCases>[0]['call'] = (
        method,
        input,
        foreign,
      ) =>
        tls.post(
          `${address}/test/notification-key/${method}`,
          foreign ? { ...(input as Record<string, unknown>), privacyDomainId: id() } : input,
        );
      const beforeWrongPolicy = provider.counters();
      await expect(
        tls.post(`${address}/test/notification-key/prepare`, custodyInput(exports[0]!), null),
      ).rejects.toThrow();
      await expect(
        tls.post(`${address}/test/notification-key/prepare`, custodyInput(exports[0]!), rogue),
      ).rejects.toThrow();
      expect(
        await custodyCall('prepare', {
          ...custodyInput(exports[0]!),
          routing: notificationSetup.wrongPolicyRouting,
        }),
      ).toMatchObject({ status: 403 });
      expect(provider.counters()).toEqual(beforeWrongPolicy);
      expect(
        (
          await admin.query(
            'select 1 from control.notification_key_preparation where participant_id=$1 and privacy_domain_id=$2 and routing_profile_id=$3',
            [
              scope.participantId,
              scope.privacyDomainId,
              notificationSetup.wrongPolicyRouting.profileId,
            ],
          )
        ).rowCount,
      ).toBe(0);
      // A service check alone is insufficient: direct runtime INSERT must bind
      // the signed routing policy to the same immutable installed KMS policy.
      const validPreparation = await custodyCall('prepare', custodyInput(exports[0]!));
      expect(validPreparation.status).toBe(200);
      const originalPreparation = validateNotificationKeyPreparation(validPreparation.body);
      const wrongRoute = (
        await admin.query<{ installation_digest: string }>(
          'select installation_digest from control.installed_notification_routing where participant_id=$1 and privacy_domain_id=$2 and profile_id=$3',
          [
            scope.participantId,
            scope.privacyDomainId,
            notificationSetup.wrongPolicyRouting.profileId,
          ],
        )
      ).rows[0]!;
      const occurrenceId = id();
      const wrongPreparation = validateNotificationKeyPreparation({
        ...originalPreparation,
        preparationId: id(),
        occurrenceId,
        input: { ...originalPreparation.input, routing: notificationSetup.wrongPolicyRouting },
        routingInstallationDigest: wrongRoute.installation_digest,
        objectIntent: {
          ...originalPreparation.objectIntent,
          payloadObjectId: id(),
          notificationOccurrenceRef: notificationOccurrenceUrn(occurrenceId),
          routingProfileDigest: notificationSetup.wrongPolicyRouting.signedProfileDigest,
        },
      });
      const wrongBytes = Buffer.from(canonicalJson(wrongPreparation));
      await expect(
        runScopedTransaction(
          runtime,
          { ...scope, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
          id,
          (client) =>
            client.query(
              `insert into control.notification_key_preparation(participant_id,privacy_domain_id,preparation_id,
             occurrence_id,payload_object_id,source_event_id,routing_profile_id,kms_installation_digest,
             preparation,preparation_bytes,preparation_digest) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
              [
                scope.participantId,
                scope.privacyDomainId,
                wrongPreparation.preparationId,
                occurrenceId,
                wrongPreparation.objectIntent.payloadObjectId,
                wrongPreparation.sourceEventId,
                wrongPreparation.input.routing.profileId,
                installationDigest,
                wrongPreparation,
                wrongBytes,
                sha256(wrongBytes),
              ],
            ),
        ),
      ).rejects.toMatchObject({ message: 'NOTIFICATION-KEY-ROUTING' });
      const joined = await assertNotificationKeyCustodyCases({
        admin,
        call: custodyCall,
        vaultDirectory,
        provider,
        cases: {
          positive: custodyInput(exports[0]!),
          rollback: custodyInput(exports[1]!),
          lostAck: custodyInput(exports[2]!),
          failedPersist: custodyInput(exports[3]!),
          unknown: custodyInput(exports[4]!),
        },
      });
      const assertKmsWithdrawalBlocked = async () => {
        const withdrawing = new Pool({
          connectionString: adminUrl,
          options: '-c role=openpc_control_owner -c lock_timeout=200ms',
          max: 1,
        });
        try {
          await expect(
            withdrawEvidenceKmsInstallation(withdrawing, recipient),
          ).rejects.toMatchObject({ code: '55P03' });
          expect(
            (
              await admin.query(
                'select state from control.evidence_kms_installation where participant_id=$1 and installation_digest=$2',
                [scope.participantId, installationDigest],
              )
            ).rows,
          ).toEqual([{ state: 'ACTIVE' }]);
        } finally {
          await withdrawing.end();
        }
      };
      await assertNotificationPayloadReferenceCases({
        installer,
        preparation: joined.positive,
        principalId,
        credentialId,
        workloadId: `urn:openpc:workload:${workloadId}`,
        tlsSpki: tlsKey,
        call: (value, missingTls) =>
          tls.post(`${address}/test/notification-reference`, value, missingTls ? null : undefined),
        publish: async () => {
          expect(
            await tls.post(`${address}/test/notification-key/source-publish`, {
              ...sourceScope,
              trustDigest: producerTrustDigest,
              evidenceExportId: joined.positive.input.evidenceExportId,
            }),
          ).toMatchObject({ status: 200, body: { state: 'PUBLISHED' } });
        },
        refresh: async () => {
          expect(
            await call('observeCurrentStatus', {
              recipient,
              attemptId: joined.positive.preparationId,
            }),
          ).toMatchObject({ status: 200 });
        },
        assertKmsWithdrawalBlocked,
        setCallback: (value) => {
          referenceCallback = value;
        },
      });
      // The preceding reference corpus revoked its own profile only. Install
      // distinct real worker identities after that terminal check, preserving its
      // missing-source, expiry, callback rollback and withdrawal-race assertions.
      occurrenceWorkers = await prepareNotificationOccurrenceWorkers({
        admin,
        installer,
        preparation: joined.positive,
        notification: occurrenceTls[0]!,
        controlWork: occurrenceTls[1]!,
      });
      const payloadReadCall: NotificationPayloadReadCall = (selector, mode, foreign) =>
        tls.post(
          `${address}/test/notification-payload/consume`,
          { selector, mode },
          foreign ? occurrenceTls[1]! : undefined,
        );
      const payloadReadSelector = {
        ...scope,
        producerTrustDigest,
        kmsInstallationDigest: installationDigest,
        preparationId: joined.positive.preparationId,
      };
      // Genuine LS-NOTIFICATION identity is trusted at TLS and installed above,
      // but has no Evidence DECRYPT recipient grant. This is not a bad-CA test.
      const beforeWorkerRead = provider.counters();
      expect(
        await tls.post(
          `${address}/test/notification-payload/consume`,
          { selector: payloadReadSelector, mode: 'CONSUME' },
          occurrenceTls[0]!,
        ),
      ).toEqual({ status: 403, body: { calls: 0, erased: true, code: 'UNAVAILABLE' } });
      expect(provider.counters()).toEqual(beforeWorkerRead);
      // The genuine source is PUBLISHED by the preceding reference corpus;
      // its payload is CUSTODIED and no occurrence has yet been published.
      expect(
        (
          await admin.query(
            'select 1 from control.notification_occurrence where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3',
            [scope.participantId, scope.privacyDomainId, joined.positive.occurrenceId],
          )
        ).rowCount,
      ).toBe(0);
      await assertNotificationPayloadReadCases({
        admin,
        call: payloadReadCall,
        readAttempt: () =>
          call('readAttempt', { recipient, attemptId: joined.positive.preparationId }),
        original: joined.positive,
        otherOriginal: joined.lostAck,
        vaultDirectory,
        provider,
      });
      const occurrenceCall = async <M extends NotificationOccurrenceCaseMethod>(
        actor: NotificationOccurrenceCaseActor,
        method: M,
        value: unknown,
      ): Promise<NotificationOccurrenceCaseResult<M>> => {
        const peer = occurrenceTls[actor === 'notification' ? 0 : 1]!;
        const result = await tls.post(
          `${address}/test/notification-occurrence/${method}`,
          value,
          peer,
        );
        if (result.status !== 200) {
          const code = (result.body as { code?: unknown })?.code;
          throw new Error(typeof code === 'string' ? code : 'Occurrence API unavailable');
        }
        return decodeNotificationOccurrenceCaseResponse(method, result.body);
      };
      const withJoinedPeer = <T>(
        peer: 'delivery' | 'completion' | 'recipient',
        run: (socket: TLSSocket) => Promise<T>,
      ): Promise<T> => {
        const token = id();
        if (joinedPeers.size >= 8) throw new Error('Joined TLS test capacity unavailable');
        let value: T,
          failure: unknown,
          failed = false,
          completed = false,
          started = false;
        let settled!: () => void;
        const settlement = new Promise<void>((resolve) => {
          settled = resolve;
        });
        joinedPeers.set(token, async (socket) => {
          started = true;
          try {
            value = await run(socket);
          } catch (error) {
            failed = true;
            failure = error;
          } finally {
            completed = true;
            settled();
          }
        });
        return (async () => {
          try {
            const response = await tls.post(
              `${address}/test/notification-joined-peer`,
              { token },
              peer === 'recipient' ? tls : occurrenceTls[peer === 'delivery' ? 0 : 1]!,
            );
            expect(response).toEqual({ status: 200, body: { completed: true } });
            expect(completed).toBe(true);
            if (failed) throw failure;
            return value!;
          } catch (transportError) {
            // Keep ownership until a started callback settles. A lost HTTP ACK
            // cannot start an independent sibling while SQL/provider work lives.
            if (started) await settlement;
            if (failed && transportError !== failure)
              throw new AggregateError(
                [failure, transportError],
                'Joined TLS operation and transport failed',
              );
            throw transportError;
          } finally {
            joinedPeers.delete(token);
          }
        })();
      };
      const occurrenceCases: NotificationOccurrenceCasesInput = {
        ...occurrenceWorkers,
        call: occurrenceCall,
        inspect: inspectOccurrence,
        publishWithLostResponse: async (value) => {
          lostOccurrenceReply = false;
          await expect(
            tls.post(
              `${address}/test/notification-occurrence/publish-lost-ack`,
              value,
              occurrenceTls[1]!,
            ),
          ).rejects.toThrow();
          expect(lostOccurrenceReply).toBe(true);
        },
        reopen: async () => {
          await app!.close();
          app = undefined;
          await runtime.end();
          runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
          kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
          state = new EvidenceKmsState(runtime, kernel);
          app = build();
          address = await app.listen({ host: '127.0.0.1', port: 0 });
        },
      };
      // TLS peer identity, scope and closed input failures precede all signing.
      await expect(
        tls.post(
          `${address}/test/notification-occurrence/prepare`,
          occurrenceWorkers.notification.input,
          null,
        ),
      ).rejects.toThrow();
      await expect(
        tls.post(
          `${address}/test/notification-occurrence/prepare`,
          occurrenceWorkers.notification.input,
          rogue,
        ),
      ).rejects.toThrow();
      await expect(
        occurrenceCall('controlWork', 'prepare', occurrenceWorkers.notification.input),
      ).rejects.toThrow('UNAVAILABLE');
      for (const changed of [
        { ...occurrenceWorkers.notification.input, ready: true },
        {
          ...occurrenceWorkers.notification.input,
          worker: { ...occurrenceWorkers.notification.input.worker, privacyDomainId: id() },
        },
        { ...occurrenceWorkers.notification.input, keyPreparationId: id() },
      ])
        await expect(occurrenceCall('notification', 'prepare', changed)).rejects.toThrow();
      const occurrenceKeyCounters = provider.counters();
      occurrenceOriginal = await assertNotificationOccurrenceCases(occurrenceCases);
      const deliverySourceSelector = {
        worker: occurrenceWorkers.deliveryWorker,
        notificationOccurrenceId: joined.positive.occurrenceId,
        eventId: occurrenceOriginal.event.claims.eventId,
      };
      const readDeliverySource = (value: unknown, peer = occurrenceTls[0]!) =>
        tls.post(`${address}/test/notification-delivery/source`, value, peer);
      expect(await readDeliverySource(deliverySourceSelector)).toMatchObject({ status: 403 });
      const refreshOccurrenceStatus = async () => {
        expect(
          await call('observeCurrentStatus', {
            recipient,
            attemptId: joined.positive.preparationId,
          }),
        ).toMatchObject({ status: 200 });
      };
      await refreshOccurrenceStatus();
      await assertNotificationOccurrenceExpiredStatus(occurrenceCases, occurrenceOriginal);
      await refreshOccurrenceStatus();
      occurrenceRollbackFailure = undefined;
      const rollbackResult = await tls.post(
        `${address}/test/notification-occurrence/rollback`,
        {},
        occurrenceTls[1]!,
      );
      if (occurrenceRollbackFailure !== undefined) throw occurrenceRollbackFailure;
      expect(rollbackResult).toMatchObject({ status: 200, body: { rolledBack: true } });
      await refreshOccurrenceStatus();
      const deliveryWorkers = occurrenceWorkers,
        originalDeliveryOccurrence = occurrenceOriginal,
        deliveryProvider = provider;
      let publishedOccurrence:
        Awaited<ReturnType<typeof assertNotificationOccurrencePublicationCases>> | undefined;
      const withdrawDeliveryWorker = () =>
        runScopedTransaction(
          installer,
          { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
          id,
          (client) => withdrawNotificationWorker(client, deliveryWorkers.deliveryWorker),
        );
      const assertDeliveryWorkerWithdrawalBlocked = () =>
        runScopedTransaction(
          installer,
          { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
          id,
          async (client) => {
            await client.query('select openpc.assert_request_context(true)');
            expect((await client.query('select current_user role')).rows).toEqual([
              { role: 'openpc_control_owner' },
            ]);
            const worker = deliveryWorkers.deliveryWorker;
            const args = [worker.participantId, worker.privacyDomainId, worker.installationDigest];
            const read = () =>
              client.query(
                'select state,installation_bytes from control.installed_notification_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3',
                args,
              );
            const before = await read();
            expect(before.rowCount).toBe(1);
            expect(before.rows[0]?.state).toBe('ACTIVE');
            expect(
              (
                await client.query(
                  "select pg_try_advisory_xact_lock(hashtextextended('notification-worker:'||$1::text||':'||$2::text,0)) allowed",
                  args.slice(0, 2),
                )
              ).rows,
            ).toEqual([{ allowed: false }]);
            await expect(withdrawNotificationWorker(client, worker)).rejects.toBeInstanceOf(
              NotificationWorkerAdmissionError,
            );
            expect((await read()).rows).toEqual(before.rows);
          },
        );
      const withDeliverySourceAdmission = async <T>(
        run: (client: PoolClient, admission: NotificationWorkerAdmission) => Promise<T>,
      ): Promise<T> => {
        let result: T | undefined,
          called = false;
        deliveryReferenceAdmissionProbe = async (client, admission) => {
          result = await run(client, admission);
          called = true;
        };
        try {
          expect(await readDeliverySource(deliverySourceSelector)).toMatchObject({ status: 200 });
          expect(called).toBe(true);
          return result as T;
        } finally {
          deliveryReferenceAdmissionProbe = undefined;
        }
      };
      await assertNotificationDeliveryPayloadReferenceCases({
        source: deliverySourceSelector,
        preparation: joined.positive,
        call: (value, missingTls) =>
          tls.post(
            `${address}/test/notification-delivery-reference`,
            value,
            missingTls ? null : occurrenceTls[0]!,
          ),
        callPublisher: (value) =>
          tls.post(`${address}/test/notification-delivery-reference`, value, occurrenceTls[1]!),
        refresh: refreshOccurrenceStatus,
        inspect: inspectOccurrence,
        setCallback: (value) => {
          referenceCallback = value;
        },
        assertKmsWithdrawalBlocked,
        assertWorkerWithdrawalBlocked: assertDeliveryWorkerWithdrawalBlocked,
        withdrawWorker: withdrawDeliveryWorker,
        withAdmission: withDeliverySourceAdmission,
        withCiphertextFault: async (mode, run) => {
          const path = join(vaultDirectory, notificationKeyFile(joined.positive));
          const metadata = await stat(path),
            bytes = await readFile(path);
          const retained = `${path}.retained`;
          try {
            if (mode === 'missing') await rename(path, retained);
            else await writeFile(path, Buffer.concat([bytes, Buffer.from(' ')]));
            await run();
          } finally {
            if (mode === 'missing') await rename(retained, path);
            else await writeFile(path, bytes);
            await chmod(path, metadata.mode & 0o777);
          }
          expect(await readFile(path)).toEqual(bytes);
          expect((await stat(path)).mode).toBe(metadata.mode);
        },
        publishDeliveryRequest: async () => {
          publishedOccurrence = await assertNotificationOccurrencePublicationCases(
            occurrenceCases,
            originalDeliveryOccurrence,
          );
          const deliverySource = await readDeliverySource(deliverySourceSelector);
          expect(deliverySource).toMatchObject({
            status: 200,
            body: {
              claims: originalDeliveryOccurrence.event.claims,
              sourceOperationId: originalDeliveryOccurrence.event.claims.operationId,
              sourceReceiptDigest: sha256(
                Buffer.from(originalDeliveryOccurrence.delivery.preparation.payloadHex, 'hex'),
              ),
            },
          });
          // Original published source and actual TLS/Identity admission are ready;
          // operations effectiveness is independently absent. Neither caller flags
          // nor a numeric fallback may reach STARTED preparation or change effects.
          const inspectPublished = () =>
            inspectOccurrence((client) =>
              assertNotificationOccurrenceAtomicState(
                client,
                originalDeliveryOccurrence,
                'PUBLISHED',
              ),
            );
          await withDeliverySourceAdmission(async (client) => {
            await client.query(
              'select openpc.assert_notification_delivery_signing_owner(),openpc.assert_notification_delivery_start_atomic_owner(),openpc.assert_notification_delivery_dispatch_owner()',
            );
            for (const table of [
              'notification_delivery_signing',
              'notification_delivery_start',
              'notification_delivery_attempt',
              'notification_delivery_dispatch_intent',
            ]) {
              const privileges = (
                await client.query(
                  `select has_table_privilege(current_user,$1,'SELECT') readable,has_table_privilege(current_user,$1,'INSERT') insertable,has_table_privilege('openpc_control_worker',$1,'INSERT') worker_insert,has_table_privilege(current_user,$1,'DELETE') deletable`,
                  [`control.${table}`],
                )
              ).rows[0];
              expect(privileges).toEqual({
                readable: true,
                insertable: true,
                worker_insert: false,
                deletable: false,
              });
              expect(
                (await client.query(`select count(*)::int n from control.${table}`)).rows[0].n,
              ).toBe(0);
            }
            expect(
              (
                await client.query(
                  "select 1 from pg_trigger where tgrelid='control.notification_delivery_attempt'::regclass and tgname='notification_delivery_attempt_closed'",
                )
              ).rowCount,
            ).toBe(0);
            const dispatch = (
              await client.query(`select
              has_table_privilege(current_user,'control.notification_delivery_dispatch_intent','UPDATE') claim,
              has_table_privilege('openpc_control_worker','control.notification_delivery_dispatch_intent','UPDATE') worker,
              exists(select 1 from pg_trigger where tgrelid='control.notification_delivery_dispatch_intent'::regclass and tgname='notification_delivery_dispatch_claim_guard' and tgenabled='O') guarded`)
            ).rows[0];
            expect(dispatch).toEqual({ claim: true, worker: false, guarded: true });
          });
          const beforeConfigurationDenial = await inspectPublished();
          const beforeConfigurationProvider = deliveryProvider.counters();
          for (const value of [
            deliverySourceSelector,
            { ...deliverySourceSelector, configuredLimit: 6, ready: true },
          ]) {
            expect(
              await tls.post(
                `${address}/test/notification-delivery/configuration`,
                value,
                occurrenceTls[0]!,
              ),
            ).toMatchObject({ status: 403, body: { code: 'UNAVAILABLE' } });
          }
          budgetDenialFailure = undefined;
          const budgetDenial = await tls.post(
            `${address}/test/notification-delivery/budget-unready`,
            deliverySourceSelector,
            occurrenceTls[0]!,
          );
          if (budgetDenialFailure !== undefined) throw budgetDenialFailure;
          expect(budgetDenial).toMatchObject({ status: 200, body: { unchanged: true } });
          preparationDenialFailure = undefined;
          const preparationDenial = await tls.post(
            `${address}/test/notification-delivery/preparation-unready`,
            deliverySourceSelector,
            occurrenceTls[0]!,
          );
          if (preparationDenialFailure !== undefined) throw preparationDenialFailure;
          expect(preparationDenial).toMatchObject({ status: 200, body: { unchanged: true } });
          expect(configurationAdmissions).toBe(0);
          expect(await inspectPublished()).toEqual(beforeConfigurationDenial);
          expect(deliveryProvider.counters()).toEqual(beforeConfigurationProvider);
          for (const value of [
            { ...deliverySourceSelector, eventId: id() },
            { ...deliverySourceSelector, notificationOccurrenceId: id() },
            { ...deliverySourceSelector, worker: deliveryWorkers.notification.input.worker },
            { ...deliverySourceSelector, worker: deliveryWorkers.controlWork.input.worker },
            {
              ...deliverySourceSelector,
              worker: { ...deliverySourceSelector.worker, privacyDomainId: id() },
            },
            { ...deliverySourceSelector, ready: true },
          ])
            expect(await readDeliverySource(value)).toMatchObject({ status: 403 });
          expect(await readDeliverySource(deliverySourceSelector, occurrenceTls[1]!)).toMatchObject(
            {
              status: 403,
            },
          );
          expect(publishedOccurrence.event.subject).toBe(
            notificationOccurrenceUrn(joined.positive.occurrenceId),
          );
          expect(publishedOccurrence.event.data.notificationOccurrenceId).toBe(
            notificationOccurrenceUrn(joined.positive.occurrenceId),
          );
          expect(
            await custodyCall('protection', {
              ...scope,
              producerTrustDigest,
              kmsInstallationDigest: installationDigest,
              preparationId: joined.positive.preparationId,
            }),
          ).toMatchObject({
            status: 200,
            body: {
              retirementAllowed: false,
              blockers: expect.arrayContaining(['OCCURRENCE_REFERENCE']),
            },
          });
          await inspectOccurrence((client) =>
            assertNotificationOccurrenceAtomicState(
              client,
              originalDeliveryOccurrence,
              'PUBLISHED',
            ),
          );
          // No additional key preparation, unwrap or transport delivery is needed
          // for publication/replay. Existing KMS effect counts below remain exact.
          expect(deliveryProvider.counters().prepareEffects).toBe(
            occurrenceKeyCounters.prepareEffects,
          );
          expect(deliveryProvider.counters().prepareCalls).toBe(occurrenceKeyCounters.prepareCalls);
          expect(deliveryProvider.counters().unwrapCalls).toBe(occurrenceKeyCounters.unwrapCalls);
          const installedRows = await inspectOccurrence((client) =>
            client.query<{ installation: unknown }>(
              'select installation from control.installed_notification_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3',
              [
                scope.participantId,
                scope.privacyDomainId,
                deliveryWorkers.deliveryWorker.installationDigest,
              ],
            ),
          );
          expect(installedRows.rowCount).toBe(1);
          const installedWorker = validateNotificationWorkerInstallation(
            installedRows.rows[0]!.installation,
            Date.now(),
          );
          const workerProfile = installedWorker.profile;
          const pins: NotificationReceiptSignerInstallation = {
            owner: 'LS-NOTIFICATION',
            purpose: notificationReceiptSigningPurpose,
            environmentId: workerProfile.environmentId,
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            installationId: id(),
            workerInstallationDigest: installedWorker.installationDigest,
            workerProfileDigest: installedWorker.input.pins.signedProfileDigest,
            workerIssuerSpkiHex: installedWorker.input.pins.issuerSpkiHex,
            principalId: workerProfile.principalId,
            workloadCredentialId: workerProfile.workloadCredentialId,
            workloadEpoch: workerProfile.workloadEpoch,
            workloadId: workerProfile.workloadId,
            secretClass: 'SECRET-SIGNING-KEY',
            secretReference: 'secret://test-notification/receipt#v1',
            secretVersion: 'v1',
            publicKeySpkiHex: workerProfile.receiptSignerSpki,
            keyEpoch: '1',
            providerId: 'notification-test',
            providerOrigin: 'https://127.0.0.1:443',
            providerTlsSpkiDigest: evidenceKeyId(
              notificationFixtureSpki(occurrenceTls[0]!.server.certificate),
            ),
            validFromNs: (BigInt(workerProfile.validFromMs) * 1000000n).toString(),
            validUntilNs: (BigInt(workerProfile.validUntilMs) * 1000000n).toString(),
            installationReference: 'real-notification-delivery-receipt-signer-test',
          };
          const signerProvider = await createNotificationReceiptProviderFixture({
            directory: join(root, 'notification-receipt-provider'),
            trust: { signer: pins, worker: installedWorker.input },
            signerPrivateKey: deliveryWorkers.notification.signerPkcs8,
            certificate: occurrenceTls[0]!.server.certificate,
            privateKey: occurrenceTls[0]!.server.privateKey,
            trustCa: occurrenceTls[0]!.server.ca,
          });
          try {
            await assertNotificationReceiptSignerInstallationCases({
              installation: signerProvider.trust.signer,
              installer: (run) =>
                runScopedTransaction(
                  installer,
                  { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
                  id,
                  run,
                ),
              withAdmission: (run) =>
                withDeliverySourceAdmission(async (client, admission) => {
                  await client.query(
                    "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
                  );
                  try {
                    return await run(client, admission);
                  } finally {
                    await client.query(
                      "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
                    );
                  }
                }),
              assertWorkerWithdrawalBlocked: assertDeliveryWorkerWithdrawalBlocked,
            });
            expect(signerProvider.counters()).toEqual({ performs: 0, lookups: 0, signatures: 0 });
          } finally {
            await signerProvider.close();
          }
        },
      });
      expect(publishedOccurrence).toBeDefined();
      await assertNotificationPayloadReadLifecycle({
        call: payloadReadCall,
        original: joined.positive,
        expectation: 'CURRENT',
        provider,
      });
      await app.close();
      app = build();
      address = await app.listen({ host: '127.0.0.1', port: 0 });
      const unknownSelector = {
        ...scope,
        producerTrustDigest,
        kmsInstallationDigest: installationDigest,
        preparationId: joined.unknown.preparationId,
      };
      expect(await custodyCall('readOriginal', unknownSelector)).toMatchObject({
        status: 200,
        body: { state: 'UNKNOWN' },
      });
      const beforeMissingOriginal = provider.counters().unwrapCalls;
      expect(await custodyCall('reconcile', unknownSelector)).toMatchObject({
        status: 403,
        body: { code: 'UNKNOWN' },
      });
      expect(provider.counters().unwrapCalls).toBe(beforeMissingOriginal);
      await assertNotificationKeyRetainedReadback({
        call: custodyCall,
        vaultDirectory,
        preparation: joined.positive,
        original: joined.original,
        expected: 'RETAINED_ALLOWED',
      });
      // Required connected sibling. Keep its first FAIL/BLOCKED while the
      // independent original KMS recovery below still runs. Canonical installs a
      // genuinely EFFECTIVE local-kms generation after the isolated missing-
      // generation corpus above; no test flag or callback can fabricate it.
      const keysBeforeCompletion = provider.counters().prepareEffects;
      let completionActor:
        Awaited<ReturnType<typeof createNotificationCompletionJourneyActor>> | undefined;
      let producerSigners:
        Awaited<ReturnType<typeof createNotificationProducerSigners>> | undefined;
      try {
        const withDeliveryPeer = <T>(run: (socket: TLSSocket) => Promise<T>) =>
          withJoinedPeer('delivery', run);
        const withRecipientPeer = <T>(run: (socket: TLSSocket) => Promise<T>) =>
          withJoinedPeer('recipient', run);
        const withCompletionPeer = <T>(run: (socket: TLSSocket) => Promise<T>) =>
          withJoinedPeer('completion', run);
        // Before any positive source preparation, budget, signing or provider I/O.
        const effective = await requireNotificationProducerGeneration({
          pool: runtime,
          kernel,
          source: deliverySourceSelector,
          withDeliveryPeer,
        });
        expect(effective.environmentId).toBe('local-kms');
        await runtime.query(
          'select openpc.assert_notification_completion_disposition_shared_owner()',
        );
        const bridgeFile = process.env.OPENPC_NOTIFICATION_COMPLETION_TEST_KEY_FILE;
        if (!bridgeFile) throw new Error('BLOCKED_NOTIFICATION_PRODUCER_NATIVE_BRIDGE');
        const bridgeKey = Buffer.from((await readFile(bridgeFile, 'utf8')).trim(), 'hex');
        try {
          installNotificationCompletionSqlBridge(runtime, bridgeKey);
        } finally {
          bridgeKey.fill(0);
        }
        const installed = async (installationDigest: string) =>
          inspectOccurrence(async (client) => {
            const rows = await client.query<{ installation: unknown }>(
              'select installation from control.installed_notification_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3',
              [scope.participantId, scope.privacyDomainId, installationDigest],
            );
            expect(rows.rowCount).toBe(1);
            return rows.rows[0]!.installation;
          });
        producerSigners = await createNotificationProducerSigners({
          owner: installer,
          workerInstallation: await installed(occurrenceWorkers!.deliveryWorker.installationDigest),
          signerPrivateKey: occurrenceWorkers!.notification.signerPkcs8,
          directory: join(root, 'joined-producer-signers'),
          tls: occurrenceTls[0]!,
        });
        completionActor = await createNotificationCompletionJourneyActor({
          owner: installer,
          controlWorker: await installed(
            occurrenceWorkers!.controlWork.input.worker.installationDigest,
          ),
          directory: join(root, 'joined-completion-signer'),
          tls: occurrenceTls[1]!,
        });
        const joinedScope = { ...scope, streamId: 'notification-completion-authentication' };
        const prepareExports = async (caseScope: typeof joinedScope, directory: string) => {
          const { mkdir } = await import('node:fs/promises');
          await mkdir(directory);
          const sourceWorker = new Pool({
            connectionString: process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL,
            max: 1,
          });
          try {
            return await prepareNotificationKeyExports({
              fixture: fixture!,
              worker: sourceWorker,
              scope: caseScope,
              root: directory,
              prepareCompletion: (evidenceExportId) =>
                tls.post(`${address}/test/notification-key/source`, {
                  ...caseScope,
                  trustDigest: producerTrustDigest,
                  evidenceExportId,
                }),
            });
          } finally {
            await sourceWorker.end();
          }
        };
        const producerExports = await prepareExports(
          joinedScope,
          join(root, 'joined-completion-exports'),
        );
        const cases: NotificationCompletionJourneyCase[] = [
          'DELIVERED_REPLAY',
          'FAILED_HUMAN',
          'LEASE_EXHAUSTED',
          'PUBLICATION_ROLLBACK',
          'COMMIT_ACK_LOST',
        ];
        expect(producerExports).toHaveLength(cases.length);
        const completionEventIds = new Set<string>();
        const prepareProducerSource = async (
          evidenceExportId: string,
          caseScope: typeof joinedScope,
        ) => {
          expect(
            await tls.post(`${address}/test/notification-key/source-publish`, {
              ...caseScope,
              trustDigest: producerTrustDigest,
              evidenceExportId,
            }),
          ).toMatchObject({ status: 200, body: { state: 'PUBLISHED' } });
          const preparedKey = await custodyCall('prepare', {
            ...custodyInput(evidenceExportId),
            scope: caseScope,
          });
          expect(preparedKey.status).toBe(200);
          const keyPreparation = validateNotificationKeyPreparation(preparedKey.body);
          completionKeyAttempts.push(keyPreparation.preparationId);
          const keySelector = {
            ...scope,
            producerTrustDigest,
            kmsInstallationDigest: installationDigest,
            preparationId: keyPreparation.preparationId,
          };
          expect(await custodyCall('seal', keySelector)).toMatchObject({
            status: 200,
            body: { state: 'CUSTODIED' },
          });
          const refresh = async () => {
            expect(
              await call('observeCurrentStatus', {
                recipient,
                attemptId: keyPreparation.preparationId,
              }),
            ).toMatchObject({ status: 200 });
          };
          await refresh();
          let publishSelector:
            | {
                worker: NonNullable<typeof occurrenceWorkers>['controlWork']['input']['worker'];
                preparationId: string;
              }
            | undefined;
          for (const role of ['notification', 'controlWork'] as const) {
            const actor = occurrenceWorkers![role];
            const occurrenceInput = {
              worker: actor.input.worker,
              source: {
                scope: caseScope,
                evidenceExportId,
                eventId: keyPreparation.sourceEventId,
              },
              keyPreparationId: keyPreparation.preparationId,
            };
            const prepared = await occurrenceCall(role, 'prepare', occurrenceInput);
            expect(prepared.state).toBe('PREPARED');
            const selector = {
              worker: actor.input.worker,
              preparationId: prepared.preparation.preparationId,
            };
            expect((await occurrenceCall(role, 'dispatch', selector)).state).toBe('DISPATCHED');
            const family =
              role === 'notification'
                ? 'NotificationOccurrenceReceiptV1'
                : 'NotificationDeliveryRequestedReceiptV1';
            const key = Buffer.from(actor.signerPkcs8);
            let signed;
            try {
              signed = signNotificationClaim(
                family,
                key,
                Buffer.from(prepared.preparation.workerProfile.receiptSignerSpki, 'hex'),
                decodeNotificationClaim(
                  family,
                  Buffer.from(prepared.preparation.payloadHex, 'hex'),
                ),
              );
            } finally {
              key.fill(0);
            }
            expect(
              (
                await occurrenceCall(role, 'observe', {
                  ...selector,
                  coseHex: signed.cose.toString('hex'),
                })
              ).state,
            ).toBe('OBSERVED');
            if (role === 'controlWork') publishSelector = selector;
          }
          expect(publishSelector).toBeDefined();
          await refresh();
          const request = await occurrenceCall('controlWork', 'publish', publishSelector!);
          expect(request.state).toBe('PUBLISHED');
          return {
            worker: occurrenceWorkers!.deliveryWorker,
            notificationOccurrenceId: keyPreparation.occurrenceId,
            eventId: request.event.id,
          };
        };
        const producerInput = (
          source: NotificationProducerJourneyInput['source'],
        ): NotificationProducerJourneyInput => ({
          pool: runtime,
          kernel,
          vaultDirectory,
          kmsTls: { ca: tls.server.ca, certificate: tls.certificate, privateKey: tls.privateKey },
          source,
          ...producerSigners!,
          credentialProvider: notificationSetup!.delivery.credentialProvider,
          withDeliveryPeer,
          withRecipientPeer,
        });
        for (const [index, kind] of cases.entries()) {
          // Each independent case has its own real export/occurrence/attempt and
          // external result. Failure does not authorize varying an existing intent.
          try {
            const evidenceExportId = producerExports[index]!;
            const source = await prepareProducerSource(evidenceExportId, joinedScope);
            const gatewayBefore = notificationSetup!.delivery.stats();
            const producer = await notificationSetup!.delivery.withOutcome(
              kind === 'FAILED_HUMAN' ? 'PERMANENT_FAILURE' : 'DELIVERED',
              () => exerciseNotificationDeliveryProducer(producerInput(source)),
            );
            expect(notificationSetup!.delivery.stats().calls - gatewayBefore.calls).toBe(1);
            expect(completionEventIds.has(producer.eventId)).toBe(false);
            completionEventIds.add(producer.eventId);
            let humanBefore: unknown;
            if (kind === 'FAILED_HUMAN') {
              const ref = `urn:openpc:resource:${producer.eventId}`;
              expect(await fixture.read(`work-items/${ref}`)).toMatchObject({
                status: 200,
                body: { kind: 'DELIVERY_FAILURE', state: 'OPEN', revision: '1' },
              });
              const action = 'ACT-OPERATIONS_UPDATE_CLAIM-V1';
              const claim = fixture.ordinaryMutation(`work-items/${ref}/claim`, action, {
                targetRef: ref,
                expectedRevision: '1',
                inputDigest: sha256({
                  actionIntentId: action,
                  targetRef: ref,
                  expectedRevision: '1',
                  transition: 'CLAIM',
                }),
              });
              expect(await claim.call()).toMatchObject({ status: 202, body: { revision: '2' } });
              humanBefore = (await fixture.read(`work-items/${ref}`)).body;
            }
            const selector = { worker: completionActor!.worker, eventId: producer.eventId };
            await exerciseNotificationCompletionJourney(
              {
                get pool() {
                  return runtime;
                },
                get kernel() {
                  return kernel;
                },
                selector,
                signerInstallationDigest: completionActor!.signerInstallationDigest,
                transport: completionActor!.transport,
                provider: completionActor!.provider,
                withPeer: withCompletionPeer,
                reopen: async () => {
                  await occurrenceCases.reopen();
                  const key = Buffer.from((await readFile(bridgeFile, 'utf8')).trim(), 'hex');
                  try {
                    installNotificationCompletionSqlBridge(runtime, key);
                  } finally {
                    key.fill(0);
                  }
                },
              },
              kind,
            );
            if (kind === 'FAILED_HUMAN')
              expect(
                (await fixture.read(`work-items/urn:openpc:resource:${producer.eventId}`)).body,
              ).toEqual(humanBefore);
          } catch (error) {
            completionFailures.push(
              new AggregateError(
                [error],
                `Notification completion ${kind} failed; dependent publication/readback blocked`,
              ),
            );
          }
        }
        // Separate governed occurrences preserve the completion corpus above.
        // No preparation is reached until the shared real async/EFFECTIVE gate passes.
        const runtimeCases: NotificationDeliveryRuntimeCase[] = [
          'SQL_DRAIN',
          'RECIPIENT_DRAIN',
          'START_SIGNING_UNKNOWN',
          'OUTCOME_SIGNING_UNKNOWN',
          'CONCURRENT_START',
        ];
        const runtimeScope = { ...scope, streamId: 'notification-runtime-authentication' };
        const runtimeExports = await prepareExports(
          runtimeScope,
          join(root, 'joined-runtime-exports'),
        );
        expect(runtimeExports).toHaveLength(runtimeCases.length);
        for (const [index, kind] of runtimeCases.entries()) {
          try {
            const source = await prepareProducerSource(runtimeExports[index]!, runtimeScope);
            await notificationSetup!.delivery.withOutcome('DELIVERED', () =>
              exerciseNotificationDeliveryRuntimeCase(kind, {
                current: () => producerInput(source),
                reopen: async () => {
                  await occurrenceCases.reopen();
                  const key = Buffer.from((await readFile(bridgeFile, 'utf8')).trim(), 'hex');
                  try {
                    installNotificationCompletionSqlBridge(runtime, key);
                  } finally {
                    key.fill(0);
                  }
                },
                signers: {
                  start: producerSigners!.providers[0]!,
                  outcome: producerSigners!.providers[1]!,
                },
                gateway: notificationSetup!.delivery,
                kms: provider!,
                barrierTimeoutMs: 30000,
              }),
            );
          } catch (error) {
            completionFailures.push(
              new AggregateError(
                [error],
                `Notification runtime ${kind} failed; dependent preparation/publication/readback blocked`,
              ),
            );
          }
        }
        expect(completionEventIds.size).toBe(cases.length);
        await completionActor.withdraw();
        const { readNotificationCompletionOriginal } =
          await import('../../../services/control-api/src/notifications/completion-disposition-state.js');
        await expect(
          withCompletionPeer((socket) =>
            readNotificationCompletionOriginal(runtime, kernel, socket, {
              worker: completionActor!.worker,
              eventId: [...completionEventIds][0]!,
            }),
          ),
        ).rejects.toThrow();
      } catch (error) {
        completionFailures.push(error);
      } finally {
        completionKeyEffects = provider.counters().prepareEffects - keysBeforeCompletion;
        for (const close of [() => producerSigners?.close(), () => completionActor?.close()]) {
          try {
            await close();
          } catch (error) {
            completionFailures.push(error);
          }
        }
      }
      provider.rotate();
      await assertNotificationPayloadReadLifecycle({
        call: payloadReadCall,
        original: joined.positive,
        expectation: 'RETAINED',
        provider,
      });
      await assertNotificationKeyRetainedReadback({
        call: custodyCall,
        vaultDirectory,
        preparation: joined.positive,
        original: joined.original,
        expected: 'RETAINED_ALLOWED',
      });
      expect(await call('open', { ...keyRequest, use: 'DECRYPT' })).toMatchObject({ status: 200 });
      const deniedCase = {
        ...payloadCase,
        attemptId: id(),
        objectIntent: {
          ...payloadCase.objectIntent,
          payloadObjectId: id(),
          notificationOccurrenceRef: `urn:openpc:notification-occurrence:${id()}`,
        },
      };
      expect(await call('prepareObjectKey', deniedCase)).toMatchObject({ status: 403 });
      expect(provider.counters().prepareEffects).toBe(9 + completionKeyEffects);
      // Use the existing real populated-store recovery owner. No table rewrite,
      // fake restoration flag or in-memory replacement can establish this case.
      // All internal connections close before that owner fences the source.
      const floorBefore = (
        await admin.query(
          `select max(provider_sequence)::text sequence from control.evidence_kms_exchange where participant_id=$1`,
          [scope.participantId],
        )
      ).rows[0].sequence;
      await app.close();
      app = undefined;
      await notificationSetup.close();
      notificationSetup = undefined;
      await fixture.close();
      fixture = undefined;
      await installer.end();
      await runtime.end();
      await admin.end();
      poolsClosed = true;
      await recovery.restore();
      // Revocation advances independent external authority after the backup.
      // The restored ACTIVE grant and old database floor must not resurrect use.
      provider.revoke();
      admin = new Pool({ connectionString: recovery.adminUrl, max: 2 });
      runtime = new Pool({ connectionString: recovery.runtimeUrl, max: 2 });
      installer = new Pool({
        connectionString: recovery.adminUrl,
        options: '-c role=openpc_control_owner',
        max: 1,
      });
      poolsClosed = false;
      kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
      state = new EvidenceKmsState(runtime, kernel);
      app = build();
      address = await app.listen({ host: '127.0.0.1', port: 0 });
      expect(await custodyCall('readOriginal', unknownSelector)).toMatchObject({
        status: 200,
        body: { state: 'UNKNOWN' },
      });
      await assertNotificationKeyRetainedReadback({
        call: custodyCall,
        vaultDirectory,
        preparation: joined.positive,
        original: joined.original,
        expected: 'REVOKED_OR_RESTORED_DENIED',
      });
      await assertNotificationPayloadReadLifecycle({
        call: payloadReadCall,
        original: joined.positive,
        expectation: 'RESTORED_REVOKED',
        provider,
      });
      expect(
        (
          await admin.query(
            `select state from control.evidence_kms_installation where participant_id=$1 and installation_digest=$2`,
            [scope.participantId, installationDigest],
          )
        ).rows[0].state,
      ).toBe('ACTIVE');
      expect(await call('open', { ...keyRequest, use: 'DECRYPT' })).toMatchObject({
        status: 403,
        body: { code: 'OPS_SECRET_REVOKED' },
      });
      const occurrenceReadbackSelector = {
        worker: occurrenceWorkers.controlWork.input.worker,
        preparationId: occurrenceOriginal.delivery.preparation.preparationId,
      };
      expect(
        await occurrenceCall('controlWork', 'readPublication', occurrenceReadbackSelector),
      ).toEqual(publishedOccurrence);
      await expect(
        occurrenceCall('controlWork', 'publish', occurrenceReadbackSelector),
      ).rejects.toThrow('UNKNOWN');
      await expect(
        occurrenceCall('controlWork', 'dispatch', occurrenceReadbackSelector),
      ).rejects.toThrow('UNKNOWN');
      await inspectOccurrence((client) =>
        assertNotificationOccurrenceAtomicState(client, occurrenceOriginal!, 'PUBLISHED'),
      );
      const retainedRecord = await admin.query<{ record_bytes: Buffer; record_cose: Buffer }>(
        `select record_bytes,record_cose
        from control.evidence_wrapped_key where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
        [scope.participantId, scope.privacyDomainId, payloadCase.attemptId],
      );
      expect(retainedRecord.rows).toEqual(originalRecord.rows);
      const floorAfter = (
        await admin.query(
          `select max(provider_sequence)::text sequence from control.evidence_kms_exchange where participant_id=$1`,
          [scope.participantId],
        )
      ).rows[0].sequence;
      expect(BigInt(floorAfter)).toBeGreaterThan(BigInt(floorBefore));
      // Neither raw material nor payload bytes may enter ordinary attempt/receipt rows.
      const retained = await admin.query(
        `select request_bytes,result_receipt_bytes from control.evidence_kms_attempt where participant_id=$1`,
        [scope.participantId],
      );
      for (const row of retained.rows)
        for (const bytes of Object.values(row))
          if (Buffer.isBuffer(bytes)) expect(bytes.includes(plaintext)).toBe(false);
      await withdrawEvidenceKmsInstallation(installer, recipient);
      expect(await call('admit', recipient)).toMatchObject({ status: 403 });
      // Metadata reconciliation survives withdrawal without granting decryption.
      expect(await call('readOriginal', selector)).toMatchObject({
        status: 200,
        body: { state: 'UNKNOWN' },
      });
      await expect(installInitialEvidenceKms(installer, pins)).rejects.toThrow(
        'OPS_SECRET_REVOKED',
      );
      const counts = await admin.query(
        `select
      (select count(*)::int from control.evidence_wrapped_key where participant_id=$1 and attempt_id<>all($3::uuid[])) wrapped,
      (select count(*)::int from control.evidence_kms_attempt where participant_id=$1 and attempt_id<>all($3::uuid[])) attempts,
      (select count(*)::int from control.authentication_occurrence where participant_id=$1 and principal_id=$2) authenticated`,
        [scope.participantId, principalId, completionKeyAttempts],
      );
      expect(counts.rows[0]).toMatchObject({ wrapped: 9, attempts: 11 });
      expect(counts.rows[0].authenticated).toBeGreaterThan(0);
      passed = completionFailures.length === 0;
    } catch (error) {
      firstFailure = error;
    } finally {
      const cleanupErrors: unknown[] = [];
      for (const cleanup of [
        () => app?.close(),
        () => notificationSetup?.close(),
        () => occurrenceWorkers?.close(),
        ...occurrenceTls.map((peer) => () => peer.close()),
        () => provider?.close(),
        () => fixture?.close(),
        () => rogue.close(),
        () => tls.close(),
        () => (poolsClosed ? undefined : installer.end()),
        () => (poolsClosed ? undefined : runtime.end()),
        () => (poolsClosed ? undefined : admin.end()),
      ]) {
        try {
          await cleanup();
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      if (cleanupErrors.length)
        firstFailure = new AggregateError(
          firstFailure === undefined ? cleanupErrors : [firstFailure, ...cleanupErrors],
          'Evidence KMS acceptance cleanup failed; original failure retained',
        );
      // Preserve the first failure and its original binary backup for diagnosis.
      if (passed && firstFailure === undefined) await rm(root, { recursive: true, force: true });
    }
    if (completionFailures.length)
      throw new AggregateError(
        firstFailure === undefined ? completionFailures : [...completionFailures, firstFailure],
        'Required notification completion acceptance FAIL/BLOCKED; original KMS result retained',
      );
    if (firstFailure !== undefined) throw firstFailure;
  },
  480000,
);
