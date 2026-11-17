import { tmpdir } from 'node:os';
import { assertNotificationRoutingInstallationCases } from './notification-routing-installation-cases.js';
import { createPrivateKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { connect as tlsConnect, TLSSocket } from 'node:tls';
import Fastify from 'fastify';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  businessTransitionProfileForOperation,
  decodeAdmittedReceipt,
  verifyReceiptCose,
  evidenceKeyId,
  signNotificationClaim,
} from '../../../packages/security-kernel/src/index.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import {
  withNotificationSecretRecipient,
  type NotificationCredentialLease,
  type NotificationSecretProvider,
  type NotificationSecretRequest,
} from '../../../services/identity-service/src/domain/notification-secret-recipient.js';
import { createLocalConfigurationAuthorizer } from '../../../services/control-api/src/configuration/local-authorizer.js';
import { registerConfigurationRoutes } from '../../../services/control-api/src/configuration/http.js';
import type {
  MutationContext,
  OperationRecord,
} from '../../../services/control-api/src/configuration/persistence/types.js';
import {
  authorizeNotificationPreparation,
  acquireNotificationInstallationFence,
  currentNotificationChannel,
  installInitialNotificationChannel,
  NotificationEndpointAdmission,
  type NotificationChannelInstallation,
} from '../../../services/control-api/src/notifications/endpoint-admission.js';
import { NotificationEndpointVerificationState } from '../../../services/control-api/src/notifications/endpoint-verification-state.js';
import { NotificationEndpointRepository } from '../../../services/control-api/src/notifications/endpoint-repository.js';
import { createNotificationVerificationRuntime } from '../../../services/control-api/src/notifications/endpoint-verification-runtime.js';
import { NotificationEndpointVerificationWorkflow } from '../../../services/control-api/src/notifications/endpoint-verification-workflow.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { digest } from './public-governance-client.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { notificationEndpointReplacementDigest } from '../../../services/control-api/src/notifications/endpoint-owner-contract.js';
import { readNotificationDeliveryCancellationCause } from '../../../services/control-api/src/notifications/delivery-cancellation-state.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import {
  encodeCbor,
  type CborValue,
} from '../../../packages/security-kernel/src/canonical-cbor.js';
import {
  decodeNotificationCredentialMaterial,
  notificationCredentialEncoding,
} from '../../../services/identity-service/src/domain/notification-credential-material.js';
import { createTestNotificationCredentialProvider } from '../../../scripts/operations/test-notification-credential-provider.js';
import { verifyInstalledNotificationChannel } from '../../../services/control-api/src/notifications/gateway-contracts.js';
import {
  parseNotificationVerificationRequest,
  verifyInstalledNotificationVerification,
  verifyNotificationVerificationResponse,
  type NotificationVerificationChallenge,
} from '../../../services/control-api/src/configuration/notification-verification-contract.js';

/** This is the existing PG/Identity family, using its existing URLs and fixture
 * owners. Missing prerequisites FAIL as BLOCKED; they are never skipped or counted
 * as a passed endpoint journey. CREATE/UPDATE exercise real signed repository
 * owners. Joined and public VERIFY call real preparation/leased dispatch/attachment
 * owners. Test composition supplies an actual workload peer and external provider;
 * production root wiring and browser acceptance remain separate obligations.
 * No endpoint, replacement candidate, challenge or observation is SQL-seeded. */
function blocked(owner: string): never {
  throw new Error(`BLOCKED notification endpoint journey: ${owner}`);
}
function databaseUrls() {
  const admin = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
  const runtime = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
  if (!admin || !runtime)
    blocked('existing OPENPC_I02_ADMIN_DATABASE_URL/RUNTIME_DATABASE_URL required');
  return { admin, runtime };
}
const operations = ['CREATE', 'UPDATE', 'VERIFY'].map(
  (command) => `CFG-OP-${command}-NOTIFICATION-ENDPOINT`,
);
const admissionTables = [
  'installed_notification_channel',
  'notification_endpoint_candidate',
  'notification_verification_attempt',
  'notification_endpoint',
  'notification_endpoint_verification',
];

async function requireAdmissionStorage(admin: Pool, runtime: Pool) {
  const result = await admin.query<{ name: string; present: boolean }>(
    `select name,to_regclass('control.'||name) is not null present from unnest($1::text[]) name`,
    [admissionTables],
  );
  const absent = result.rows.filter((r) => !r.present).map((r) => r.name);
  if (absent.length)
    blocked(`canonical generated admission migration missing: ${absent.join(', ')}`);
  const role = await runtime.query<{ allowed: boolean }>(
    `select pg_has_role(current_user,'openpc_control_runtime','MEMBER')
      and not rolbypassrls and not rolsuper
      and has_table_privilege(current_user,'control.installed_notification_channel','SELECT')
      and not has_table_privilege(current_user,'control.installed_notification_channel','INSERT,UPDATE,DELETE') allowed
      from pg_roles where rolname=current_user`,
  );
  if (role.rowCount !== 1 || role.rows[0]?.allowed !== true)
    blocked('canonical scoped runtime role and narrow installation grants');
  const guards = await admin.query<{ name: string; present: boolean }>(
    `select name,to_regprocedure(name) is not null present from unnest($1::text[]) name`,
    [
      [
        'openpc.guard_notification_channel_installation()',
        'openpc.guard_notification_candidate()',
        'openpc.guard_notification_verification_attempt()',
        'openpc.guard_notification_verification_row()',
      ],
    ],
  );
  const missing = guards.rows.filter((r) => !r.present).map((r) => r.name);
  if (missing.length) blocked(`canonical generated security tail missing: ${missing.join(', ')}`);
}

// These rows are initial signing trust, installed by the existing signing fixture.
// Check their exact canonical identity after installation, before channel/business work.
async function requireInstalledBusinessProfiles(admin: Pool) {
  const found = await admin.query<{ catalog_operation_id: string; profile_digest: Buffer }>(
    `select catalog_operation_id,profile_digest from control.business_transition_profile
      where catalog_operation_id=any($1::text[]) and profile_version=1 order by catalog_operation_id`,
    [operations],
  );
  for (const operation of operations) {
    const profile = businessTransitionProfileForOperation(operation)!;
    const rows = found.rows.filter((r) => r.catalog_operation_id === operation);
    if (
      rows.length !== 1 ||
      !rows[0]!.profile_digest.equals(Buffer.from(profile.profileDigest.slice(7), 'hex'))
    )
      blocked(`exact admitted PostgreSQL business profile ${operation}`);
  }
}

it('checks actual endpoint persistence prerequisites before allocating the connected service journey', async () => {
  const missingProfiles = operations.filter((op) => !businessTransitionProfileForOperation(op));
  if (missingProfiles.length)
    blocked(`canonical generated business transition profiles: ${missingProfiles.join(', ')}`);
  const urls = databaseUrls();
  const admin = new Pool({ connectionString: urls.admin, max: 1 });
  const runtime = new Pool({ connectionString: urls.runtime, max: 1 });
  try {
    await requireAdmissionStorage(admin, runtime);
    const admission = await admin.query<{ ready: boolean }>(
      `select to_regprocedure('openpc.assert_notification_endpoint_persistence(text,bytea)') is not null ready`,
    );
    if (admission.rows[0]?.ready !== true) blocked('operation-specific SQL persistence admission');
    // Evaluate the installed CHECK itself, without inserting a fabricated
    // signing request or any intermediate business state. SQL NULL must reject.
    const constraints = await runtime.query<{ expression: string }>(
      `select pg_get_expr(conbin,conrelid) expression from pg_constraint
        where conrelid='control.notification_cancellation_signing'::regclass
          and conname='notification_cancel_signing_state_ck' and contype='c'`,
    );
    expect(constraints.rowCount).toBe(1);
    for (const [state, token, at, expected] of [
      ['PREPARED', null, null, true],
      ['DISPATCHED', id(), '1', true],
      ['DISPATCHED', id(), null, false],
      ['OBSERVED', id(), null, false],
    ] as const) {
      const checked = await runtime.query(
        `select (${constraints.rows[0]!.expression}) value from
          (select $1::text state,$2::uuid dispatch_token,$3::numeric dispatched_at_ms,
            null::jsonb observation,null::bytea observation_bytes,null::text observation_digest) value`,
        [state, token, at],
      );
      expect(checked.rows[0]?.value).toBe(expected);
    }
    // This test establishes only the database preflight. It is not named or
    // reported as a completed endpoint journey. The exact missing fixture owners
    // below are published in the task result, not bypassed with a local signer or
    // invented provider callback:
    // - contractAdministrationFixture / ConfigurationApiOptions: endpoint roots;
    // - installed physical NotificationSecretProvider.withExactVersion and
    //   consumption of those same leased bytes by the gateway SecureContext.
  } finally {
    await runtime.end();
    await admin.end();
  }
});

it('commits endpoint metadata and joined verification through real Identity, leased TLS and signed PG owners', async () => {
  const urls = databaseUrls();
  const admin = new Pool({ connectionString: urls.admin, max: 2 });
  // One source slot deliberately exercises concurrent mutations without a second pooled checkout.
  const runtime = new Pool({ connectionString: urls.runtime, max: 1 });
  let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
  let tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>> | undefined;
  let app: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
  let signingKey: Buffer | undefined;
  let signing: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>> | undefined;
  try {
    await requireAdmissionStorage(admin, runtime);
    const participantId = id(),
      privacyDomainId = id(),
      principalId = id(),
      credentialId = id(),
      workloadId = id();
    fixture = await contractAdministrationFixture(
      admin,
      urls.runtime,
      participantId,
      privacyDomainId,
      {
        notificationEndpointOwners: (pool, verifier) =>
          new NotificationEndpointVerificationState(pool, verifier),
      },
    );
    signing = await evidenceGovernanceSigningFixture(
      admin,
      participantId,
      privacyDomainId,
      'notification-endpoint',
    );
    await requireInstalledBusinessProfiles(admin);
    const uriSan = `urn:openpc:participant:${participantId}:workload:${workloadId}`;
    tls = await runtimeSnapshotTlsFixture(uriSan);
    const spki = tls.parsed.publicKey.export({ format: 'der', type: 'spki' });
    // Initial trust only, matching postgres-secret-recipient's existing fixture
    // pattern. Authentication still uses the actual TLS socket and Identity kernel.
    await admin.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Notification recipient initial trust','ACTIVE',1)`,
      [principalId, participantId],
    );
    await admin.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-evidence-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
      [
        credentialId,
        participantId,
        principalId,
        uriSan,
        `urn:openpc:workload:${workloadId}`,
        Buffer.from(sha256(spki).slice(7), 'hex'),
        spki,
        Buffer.from(sha256(tls.parsed.raw).slice(7), 'hex'),
        new Date(tls.parsed.validFrom),
        new Date(tls.parsed.validTo),
      ],
    );
    const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    signingKey = issuer.privateKey.export({ format: 'der', type: 'pkcs8' });
    const issuerSpki = issuer.publicKey.export({ format: 'der', type: 'spki' });
    const externalSigner = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export(
      { format: 'der', type: 'spki' },
    );
    const now = Date.now(),
      destinationRef = `urn:openpc:resource:${id()}`,
      credentialRef = `urn:openpc:resource:${id()}`;
    const transport = {
      protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1' as const,
      channel: 'WEBHOOK' as const,
      destinationRef,
      credentialRef,
      endpoint: 'https://127.0.0.1/',
      addresses: ['127.0.0.1'],
      serverSpkiDigest: sha256(
        new X509Certificate(tls.server.certificate).publicKey.export({
          format: 'der',
          type: 'spki',
        }),
      ),
      requestTimeoutMs: 5000,
      maxPayloadBytes: 1024,
    };
    const signed = signNotificationClaim('NotificationChannelProfileV1', signingKey, issuerSpki, {
      environmentId: 'notification-endpoint-postgres',
      participantId,
      privacyDomainId,
      profileId: id(),
      revision: '1',
      validFromMs: now - 1000,
      validUntilMs: now + 3600000,
      transportProfileDigest: sha256(transport),
      receiptSignerSpki: externalSigner.toString('hex'),
      issuerKeyId: evidenceKeyId(issuerSpki),
    });
    const installation: NotificationChannelInstallation = {
      credential: {
        participantId,
        privacyDomainId,
        credentialRef,
        channel: 'WEBHOOK',
        destinationRef,
        secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
        owner: 'LS-NOTIFICATION',
        reference: 'secret://local/notification-mtls#1',
        version: '1',
        fingerprint: sha256(tls.privateKey),
        epoch: '1',
        validFromMs: now - 1000,
        validUntilMs: now + 3600000,
        state: 'ACTIVE',
      },
      channelTrust: {
        environmentId: 'notification-endpoint-postgres',
        participantId,
        privacyDomainId,
        signedProfileDigest: sha256(signed.cose),
        issuerSpkiHex: issuerSpki.toString('hex'),
      },
      channelSigned: {
        transport,
        payloadHex: signed.payload.toString('hex'),
        coseHex: signed.cose.toString('hex'),
      },
      principalId,
      workloadCredentialId: credentialId,
      workloadId: `urn:openpc:workload:${workloadId}`,
      workloadEpoch: '1',
      admissionReference: 'PostgreSQL notification initial metadata only',
    };
    const install = async (value: NotificationChannelInstallation) => {
      const client = await admin.connect();
      try {
        await client.query('begin');
        await installInitialNotificationChannel(client, value);
        await client.query('commit');
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
    };
    const assertInstallationFenceReleased = async () => {
      const client = await admin.connect();
      try {
        await client.query('begin');
        const lock = await client.query<{ acquired: boolean }>(
          "select pg_try_advisory_xact_lock(hashtextextended('notification-installation:'||$1::text||':'||$2::text,0)) acquired",
          [participantId, privacyDomainId],
        );
        expect(lock.rows[0]?.acquired).toBe(true);
      } finally {
        await client.query('rollback');
        client.release();
      }
    };
    const rejectConcurrentRevocation = async (reference: string) => {
      const client = await admin.connect();
      try {
        await client.query('begin');
        await client.query("set local lock_timeout='500ms'");
        await client.query("set local statement_timeout='1s'");
        // The direct UPDATE reaches the real row trigger, which must fail fast
        // on its reversed row/advisory order rather than wait or enlarge grants.
        await expect(
          client.query(
            "update control.installed_notification_channel set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3",
            [participantId, privacyDomainId, reference],
          ),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
      } finally {
        await client.query('rollback');
        client.release();
      }
    };
    const stored = async () =>
      (
        await admin.query(
          `select * from control.installed_notification_channel where participant_id=$1 order by credential_ref`,
          [participantId],
        )
      ).rows;
    const effects = async () =>
      (
        await admin.query(
          `select
      (select count(*)::int from control.notification_endpoint where participant_id=$1) endpoints,
      (select count(*)::int from control.notification_endpoint_candidate where participant_id=$1) candidates,
      (select count(*)::int from control.notification_verification_attempt where participant_id=$1) challenges,
      (select count(*)::int from control.notification_endpoint_verification where participant_id=$1) verifications,
      (select count(*)::int from control.audit_occurrence where participant_id=$1 and aggregate_type='notification-endpoint') receipts,
      (select count(*)::int from control.outbox_event where participant_id=$1 and aggregate_type='notification-endpoint') outbox,
      (select count(*)::int from control.idempotency_record where participant_id=$1 and catalog_operation_id=any($2::text[])) operations`,
          [participantId, operations],
        )
      ).rows[0];
    const originalEffects = await effects();
    expect(originalEffects).toEqual({
      endpoints: 0,
      candidates: 0,
      challenges: 0,
      verifications: 0,
      receipts: 0,
      outbox: 0,
      operations: 0,
    });
    await install(installation);
    const original = await stored();
    expect(original).toHaveLength(1);
    expect(original[0].verification_trust).toBeNull();
    expect(original[0].verification_signed).toBeNull();
    await install(installation);
    expect(await stored()).toEqual(original);
    const selected = () =>
      runScopedTransaction(
        runtime,
        {
          participantId,
          privacyDomainId,
          actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_READ_COLLECTION-V1',
        },
        id,
        (client) =>
          currentNotificationChannel(client, { participantId, privacyDomainId }, credentialRef),
      );
    const selectedMetadata = await selected();
    expect(selectedMetadata.credential).toEqual(installation.credential);
    expect(selectedMetadata.verification).toBeUndefined();
    expect(await effects()).toEqual(originalEffects);

    // Independent malformed/admission-denial siblings preserve the initial state.
    for (const value of [
      { ...installation, admissionReference: 'Changed original installation' },
      { ...installation, credential: { ...installation.credential, participantId: id() } },
      { ...installation, credential: { ...installation.credential, state: 'REVOKED' as const } },
      {
        ...installation,
        credential: { ...installation.credential, validFromMs: now - 2000, validUntilMs: now - 1 },
      },
      {
        ...installation,
        credential: {
          ...installation.credential,
          reference: 'secret://local/notification-mtls#2',
          version: '1',
        },
      },
      {
        ...installation,
        channelSigned: {
          ...installation.channelSigned,
          coseHex: `${installation.channelSigned.coseHex.slice(0, -2)}${installation.channelSigned.coseHex.endsWith('00') ? '01' : '00'}`,
        },
      },
      {
        ...installation,
        channelTrust: {
          ...installation.channelTrust,
          signedProfileDigest: `sha256:${'0'.repeat(64)}`,
        },
      },
    ]) {
      await expect(install(value)).rejects.toThrow();
      expect(await stored()).toEqual(original);
      expect(await effects()).toEqual(originalEffects);
    }
    const denied = await runtime.connect();
    try {
      await denied.query('begin');
      await expect(installInitialNotificationChannel(denied, installation)).rejects.toThrow(
        'PC-DATA-6007',
      );
      await denied.query('rollback');
      await expect(
        denied.query('update control.installed_notification_channel set state=state'),
      ).rejects.toMatchObject({ code: '42501' });
    } finally {
      denied.release();
    }

    for (const actor of ['maker', 'checker'] as const) {
      await fixture.governance.client.stepUp(
        fixture.governance[actor],
        'ACT-IDENTITY_CREATE_SESSION-V1',
        participantId,
        digest({ participantId, privacyDomainId }),
      );
      await fixture.selectPrivacyContext(actor);
    }
    const { client, maker, checker } = fixture.governance;
    const authorizer = createLocalConfigurationAuthorizer(
      fixture.service.identityUrl,
      fixture.service.identityInternalToken,
      privacyDomainId,
    );
    const verifier = createLocalIdentityRuntimeVerifier([
      await readFile(`${fixture.service.directory}/public.der`),
    ]);
    const resourceId = id(),
      actionIntentId = 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1';
    const body = {
      actionIntentId,
      actionIntentDigest: client.actionDigests.get(actionIntentId)!,
      participantId: `urn:openpc:participant:${participantId}`,
      channel: 'WEBHOOK' as const,
      destinationRef,
      arbitraryEgress: false as const,
      reason: 'Construct disabled metadata using current installed owners.',
    };
    const input = {
      sessionToken: maker.sessionToken,
      participantId,
      privacyDomainId,
      resourceId,
      catalogOperationId: operations[0]!,
      idempotencyKey: `notification-endpoint-${id()}`,
      actionIntentId,
      actionIntentDigest: body.actionIntentDigest,
      candidateDigest: digest(body),
      expectedRevision: '0',
      makerCheckerRequired: false,
      stepUpRequired: true,
      origin: fixture.service.identityUrl,
      host: new URL(fixture.service.identityUrl).host,
      csrfToken: await client.csrf(maker, actionIntentId, fixture.service.identityUrl),
    };
    await expect(authorizer.authorize(input)).rejects.toThrow('PC-AUTH-0005');
    await client.stepUp(checker, actionIntentId, resourceId, digest(body));
    await expect(authorizer.authorize(input)).rejects.toThrow('PC-AUTH-0005');
    await client.stepUp(maker, actionIntentId, resourceId, digest(body));
    const proof = await authorizer.authorize(input);
    if (proof.evidenceKind !== 'IDENTITY_RUNTIME_STEP_UP')
      throw new Error('Expected actual fresh actor step-up');
    const context: MutationContext = {
      authorization: proof,
      sessionToken: maker.sessionToken,
      actionIntentId,
      actionIntentDigest: body.actionIntentDigest,
      catalogOperationId: input.catalogOperationId,
      idempotencyKey: input.idempotencyKey,
      resourceId,
      resourceType: 'notification-endpoints',
      aggregateType: 'notification-endpoint',
      operationClass: 'CREATE',
      expectedRevision: '0',
      candidate: body,
    };
    const admission = new NotificationEndpointAdmission(runtime, verifier);
    const prepared = await runScopedTransaction(
      runtime,
      { participantId, privacyDomainId, actionIntentId },
      id,
      async (connection) => {
        await authorizeNotificationPreparation(connection, context, verifier);
        return admission.resolveCreate(connection, context, body);
      },
    );
    expect(prepared.binding).toMatchObject({
      participantId,
      privacyDomainId,
      endpointId: resourceId,
      revision: '1',
      channel: 'WEBHOOK',
      destinationRef,
      credentialRef,
    });
    expect(prepared.credential).toEqual(installation.credential);
    expect(await effects()).toEqual(originalEffects);
    // A real prepared descriptor is insufficient for signed mutation. No fake
    // evidence signer, direct endpoint INSERT, or fabricated owner result fills it.
    const owners = new NotificationEndpointVerificationState(runtime, verifier);
    const repository = new NotificationEndpointRepository(runtime, verifier, undefined, owners);
    await expect(repository.create(context, body)).rejects.toThrow('PC-INTEGRATION-5001');
    expect(await effects()).toEqual(originalEffects);
    const stepUpUse = await admin.query(
      `select count(*)::int n from control.mfa_challenge where participant_id=$1 and action_intent_id=$2 and used_at is not null`,
      [participantId, actionIntentId],
    );
    expect(stepUpUse.rows[0].n).toBe(0);

    // Genuine TLS/Identity denials precede any physical provider invocation.
    // This sentinel NEVER supplies bytes or substitutes for provider readiness.
    let providerCalls = 0,
      consumerCalls = 0;
    const unavailableProvider: NotificationSecretProvider = {
      async withExactVersion() {
        providerCalls++;
        return blocked('canonical physical notification provider withExactVersion not supplied');
      },
    };
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
    const request: NotificationSecretRequest = {
      participantId,
      privacyDomainId,
      credentialRef,
      reference: installation.credential.reference,
      version: '1',
      epoch: '1',
    };
    app = buildLocalWorkloadMtlsService(runtime, kernel, tls.server);
    app.post('/test/notification-recipient', async (req, reply) => {
      try {
        await withNotificationSecretRecipient(
          runtime,
          kernel,
          req.raw.socket as TLSSocket,
          req.body as NotificationSecretRequest,
          unavailableProvider,
          async () => {
            consumerCalls++;
          },
        );
        return { ok: true };
      } catch {
        return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
      }
    });
    const address = await app.listen({ host: '127.0.0.1', port: 0 });
    for (const changed of [
      { ...request, version: '2' },
      { ...request, reference: 'secret://local/another#1' },
      { ...request, epoch: '2' },
      { ...request, participantId: id() },
      { ...request, privacyDomainId: id() },
      { ...request, credentialRef: `urn:openpc:resource:${id()}` },
      { ...request, consumer: 'LS-FACT-BRIDGE' },
      { ...request, secretClass: 'SECRET-DB-CREDENTIAL' },
    ]) {
      expect(await tls.post(`${address}/test/notification-recipient`, changed)).toMatchObject({
        status: 403,
      });
      expect(providerCalls).toBe(0);
      expect(consumerCalls).toBe(0);
    }
    await expect(
      tls.post(`${address}/test/notification-recipient`, request, null),
    ).rejects.toThrow();
    expect(providerCalls).toBe(0);
    expect(consumerCalls).toBe(0);
    expect(await effects()).toEqual(originalEffects);
    expect(await stored()).toEqual(original);
    await app.close();
    app = undefined;
    // Restart readback re-instantiates real owners from the same admitted rows.
    const renewed = await authorizer.authorize(input);
    if (renewed.evidenceKind !== 'IDENTITY_RUNTIME_STEP_UP')
      throw new Error('Expected renewed authentication for original intent');
    const restartContext = { ...context, authorization: renewed };
    const restarted = new NotificationEndpointAdmission(runtime, verifier);
    const again = await runScopedTransaction(
      runtime,
      { participantId, privacyDomainId, actionIntentId },
      id,
      async (connection) => {
        await authorizeNotificationPreparation(connection, restartContext, verifier);
        return restarted.resolveCreate(connection, restartContext, body);
      },
    );
    expect(again).toEqual(prepared);
    expect(await stored()).toEqual(original);
    expect(await effects()).toEqual(originalEffects);
    // Real business transitions now use the existing signing fixture's exact
    // three endpoint profiles. No local signer or hand-built grant replaces it.
    const originalSigner = signing.evidence.signer;
    let probeRevocationDuringSigning = false,
      signingFenceProbes = 0;
    const fencedEvidence = {
      ...signing.evidence,
      signer: {
        sign: async (...args: Parameters<typeof originalSigner.sign>) => {
          const result = await originalSigner.sign(...args);
          if (probeRevocationDuringSigning) {
            await rejectConcurrentRevocation(credentialRef);
            signingFenceProbes++;
          }
          return result;
        },
      },
    };
    const signedRepository = new NotificationEndpointRepository(
      runtime,
      verifier,
      fencedEvidence,
      new NotificationEndpointVerificationState(runtime, verifier),
    );
    const grants = await admin.query(
      `select encode(profile_digest,'hex') digest from control.business_signing_grant where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 order by profile_digest`,
      [participantId, privacyDomainId, signing.trust.signerId],
    );
    expect(grants.rows.map((r) => r.digest)).toEqual(
      operations
        .map((op) => businessTransitionProfileForOperation(op)!.profileDigest.slice(7))
        .sort(),
    );
    const currentProof = await authorizer.authorize(input);
    if (currentProof.evidenceKind !== 'IDENTITY_RUNTIME_STEP_UP')
      throw new Error('Expected actual step-up for CREATE');
    const createContext = { ...context, authorization: currentProof };
    for (const fault of ['UNAVAILABLE', 'CORRUPT'] as const) {
      signing.faults.mode = fault;
      await expect(signedRepository.create(createContext, body)).rejects.toThrow();
      expect(await effects()).toEqual(originalEffects);
      await assertInstallationFenceReleased();
    }
    signing.faults.mode = undefined;
    const functionName = 'test_notification_endpoint_outbox_failure';
    await admin.query(`create function openpc.${functionName}() returns trigger language plpgsql as $$
      begin if NEW.aggregate_type='notification-endpoint' and NEW.participant_id='${participantId}'::uuid
        then raise exception 'TEST_NOTIFICATION_ENDPOINT_OUTBOX_FAILURE'; end if; return NEW; end $$;
      create trigger ${functionName} before insert on control.outbox_event for each row execute function openpc.${functionName}()`);
    try {
      const calls = signing.faults.calls;
      await expect(signedRepository.create(createContext, body)).rejects.toThrow(
        'TEST_NOTIFICATION_ENDPOINT_OUTBOX_FAILURE',
      );
      expect(signing.faults.calls).toBe(calls + 1);
      expect(await effects()).toEqual(originalEffects);
      await assertInstallationFenceReleased();
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.mfa_challenge where participant_id=$1 and action_intent_id=$2 and used_at is not null`,
            [participantId, actionIntentId],
          )
        ).rows[0].n,
      ).toBe(0);
    } finally {
      await admin.query(
        `drop trigger ${functionName} on control.outbox_event; drop function openpc.${functionName}()`,
      );
    }
    const preSnapshot = await acquireNotificationInstallationFence(
      runtime,
      createContext,
      verifier,
    );
    try {
      // Revocation is already excluded even BEFORE any SERIALIZABLE business snapshot.
      await rejectConcurrentRevocation(credentialRef);
      const business = await preSnapshot.mutationPool.connect();
      try {
        await business.query('begin isolation level serializable');
        await business.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          participantId,
          privacyDomainId,
          id(),
          actionIntentId,
        ]);
        await business.query(
          'select participant_id from control.participant where participant_id=$1',
          [participantId],
        );
        await rejectConcurrentRevocation(credentialRef);
        expect(
          (
            await currentNotificationChannel(
              business,
              { participantId, privacyDomainId },
              credentialRef,
            )
          ).credential,
        ).toEqual(installation.credential);
        await preSnapshot.revalidate();
      } finally {
        await business.query('rollback');
        business.release();
      }
    } finally {
      await preSnapshot.release();
    }
    await assertInstallationFenceReleased();
    // One genuine PostgreSQL serialization failure after signing/outbox work.
    // Sequence state survives transaction rollback solely as a fault-injection counter.
    const retryName = `test_notification_retry_${resourceId.replaceAll('-', '')}`;
    await admin.query(`create sequence openpc.${retryName};
      grant usage,select on sequence openpc.${retryName} to openpc_control_runtime;
      create function openpc.${retryName}() returns trigger language plpgsql as $$ begin
        if NEW.aggregate_type='notification-endpoint' and NEW.participant_id='${participantId}'::uuid
          and nextval('openpc.${retryName}')=1 then raise exception using errcode='40001',message='TEST_NOTIFICATION_SERIALIZATION'; end if;
        return NEW; end $$;
      create trigger ${retryName} before insert on control.outbox_event for each row execute function openpc.${retryName}()`);
    let created: Awaited<ReturnType<NotificationEndpointRepository['create']>>;
    const callsBeforeRetry = signing.faults.calls;
    probeRevocationDuringSigning = true;
    try {
      created = await signedRepository.create(createContext, body);
      expect(signing.faults.calls).toBe(callsBeforeRetry + 2);
      expect(signingFenceProbes).toBe(2);
      expect(
        (await admin.query(`select last_value::text from openpc.${retryName}`)).rows[0].last_value,
      ).toBe('2');
    } finally {
      probeRevocationDuringSigning = false;
      await admin.query(
        `drop trigger ${retryName} on control.outbox_event; drop function openpc.${retryName}(); drop sequence openpc.${retryName}`,
      );
    }
    await assertInstallationFenceReleased();
    expect(created).toMatchObject({
      state: 'SUCCEEDED',
      truthState: 'SUCCESS',
      resourceRef: `urn:openpc:resource:${resourceId}`,
      revision: '1',
    });
    expect(await signedRepository.create(createContext, body)).toEqual(created);
    const afterCreate = await effects();
    expect(afterCreate).toEqual({
      ...originalEffects,
      endpoints: 1,
      receipts: 1,
      outbox: 1,
      operations: 1,
    });
    const actual = async () =>
      (
        await admin.query(
          `select participant_id,privacy_domain_id,endpoint_id,channel,destination_ref,channel_profile_digest,credential_ref,state,revision::text,verification_id,candidate_digest
      from control.notification_endpoint where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3`,
          [participantId, privacyDomainId, resourceId],
        )
      ).rows[0];
    const first = await actual();
    expect(first).toMatchObject({
      state: 'DISABLED',
      revision: '1',
      verification_id: null,
      credential_ref: credentialRef,
      destination_ref: destinationRef,
    });
    await expect(
      signedRepository.create(
        { ...createContext, candidate: { ...body, reason: 'Changed original intent' } },
        { ...body, reason: 'Changed original intent' },
      ),
    ).rejects.toThrow();
    expect(await effects()).toEqual(afterCreate);
    // Register another initial immutable provider version; the endpoint changes
    // only through its real preparation/step-up/AtomicConfigurationMutation path.
    const nextCredentialRef = `urn:openpc:resource:${id()}`,
      nextDestination = `urn:openpc:resource:${id()}`;
    const nextTransport = {
      ...transport,
      credentialRef: nextCredentialRef,
      destinationRef: nextDestination,
    };
    const nextSigned = signNotificationClaim(
      'NotificationChannelProfileV1',
      signingKey,
      issuerSpki,
      {
        environmentId: 'notification-endpoint-postgres',
        participantId,
        privacyDomainId,
        profileId: id(),
        revision: '1',
        validFromMs: now - 1000,
        validUntilMs: now + 3600000,
        transportProfileDigest: sha256(nextTransport),
        receiptSignerSpki: externalSigner.toString('hex'),
        issuerKeyId: evidenceKeyId(issuerSpki),
      },
    );
    const nextInstallation: NotificationChannelInstallation = {
      ...installation,
      credential: {
        ...installation.credential,
        credentialRef: nextCredentialRef,
        destinationRef: nextDestination,
        reference: 'secret://local/notification-mtls#2',
        version: '2',
        epoch: '2',
      },
      channelTrust: { ...installation.channelTrust, signedProfileDigest: sha256(nextSigned.cose) },
      channelSigned: {
        transport: nextTransport,
        payloadHex: nextSigned.payload.toString('hex'),
        coseHex: nextSigned.cose.toString('hex'),
      },
      admissionReference: 'Separate initial immutable version for governed replacement',
    };
    await install(nextInstallation);
    const predecessor = {
      participantId: first.participant_id,
      privacyDomainId: first.privacy_domain_id,
      endpointId: first.endpoint_id,
      revision: first.revision,
      channel: prepared.binding.channel,
      destinationRef: first.destination_ref,
      channelProfileDigest: first.channel_profile_digest,
      credentialRef: first.credential_ref,
    };
    const replacement = {
      binding: {
        ...predecessor,
        revision: '2',
        destinationRef: nextDestination,
        channelProfileDigest: nextInstallation.channelTrust.signedProfileDigest,
        credentialRef: nextCredentialRef,
      },
      credential: nextInstallation.credential,
    };
    const updateAction = 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1';
    const updateBody = {
      actionIntentId: updateAction,
      actionIntentDigest: client.actionDigests.get(updateAction)!,
      expectedRevision: '1',
      replacementDigest: notificationEndpointReplacementDigest(predecessor, replacement),
      reason: 'Replace exact admitted metadata and remain disabled.',
    };
    const updateInput = {
      ...input,
      actionIntentId: updateAction,
      actionIntentDigest: updateBody.actionIntentDigest,
      catalogOperationId: operations[1]!,
      idempotencyKey: `notification-endpoint-replacement-${id()}`,
      candidateDigest: digest(updateBody),
      expectedRevision: '1',
      csrfToken: await client.csrf(maker, updateAction, fixture.service.identityUrl),
    };
    await expect(authorizer.authorize(updateInput)).rejects.toThrow('PC-AUTH-0005');
    await client.stepUp(maker, updateAction, resourceId, digest(updateBody));
    const updateProof = await authorizer.authorize(updateInput);
    if (updateProof.evidenceKind !== 'IDENTITY_RUNTIME_STEP_UP')
      throw new Error('Expected actual actor-only UPDATE step-up');
    expect(updateProof.approvalRequestId).toBeUndefined();
    expect(updateProof.checkerPrincipalId).toBeUndefined();
    const updateContext: MutationContext = {
      ...context,
      authorization: updateProof,
      actionIntentId: updateAction,
      actionIntentDigest: updateBody.actionIntentDigest,
      catalogOperationId: updateInput.catalogOperationId,
      idempotencyKey: updateInput.idempotencyKey,
      operationClass: 'UPDATE',
      expectedRevision: '1',
      candidate: updateBody,
    };
    // Public selection discloses only reviewed choices. PATCH must admit its
    // immutable candidate itself; no internal preparation or database seeding.
    const afterPreparation = { ...afterCreate, candidates: 1 };
    expect(await effects()).toEqual(afterCreate);
    const metadataApp = Fastify({ logger: false });
    registerConfigurationRoutes(metadataApp, {
      pool: runtime,
      authorizer,
      identityRuntimeVerifier: verifier,
      businessEvidence: fencedEvidence,
      notificationEndpointOwners: owners,
    });
    let updated: OperationRecord;
    try {
      const headers = {
        'cookie': `__Host-openpc_session=${maker.sessionToken}`,
        'openpc-api-version': '1',
        'openpc-participant-id': `urn:openpc:participant:${participantId}`,
        'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
        'x-request-id': id(),
        'x-correlation-id': id(),
      };
      const path = `/api/v1/notification-endpoints/urn:openpc:resource:${resourceId}`;
      const choices = await metadataApp.inject({
        method: 'GET',
        url: `${path}/replacements`,
        headers,
      });
      expect(choices.statusCode).toBe(200);
      expect(choices.json()).toMatchObject({
        notificationEndpointId: `urn:openpc:resource:${resourceId}`,
        revision: '1',
        authority: 'NONE',
        items: expect.arrayContaining([
          {
            channel: 'WEBHOOK',
            destinationRef: nextDestination,
            replacementDigest: updateBody.replacementDigest,
          },
        ]),
      });
      expect(choices.body).not.toMatch(
        /credential|fingerprint|secret:|profile|workload|principal|session/i,
      );
      const denied = await metadataApp.inject({
        method: 'GET',
        url: `${path}/replacements`,
        headers: { ...headers, 'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${id()}` },
      });
      expect([403, 404]).toContain(denied.statusCode);
      expect(denied.body).not.toContain(updateBody.replacementDigest);
      expect(await effects()).toEqual(afterCreate);
      const mutateHeaders = {
        ...headers,
        'idempotency-key': updateInput.idempotencyKey,
        'openpc-action-intent-digest': updateBody.actionIntentDigest,
        'if-match': `"${digest({ resourceId, revision: '1' })}"`,
        'x-csrf-token': updateInput.csrfToken,
        'origin': fixture.service.identityUrl,
        'host': new URL(fixture.service.identityUrl).host,
      };
      for (const invalid of [
        { ...updateBody, replacementDigest: `sha256:${'f'.repeat(64)}` },
        { ...updateBody, credentialRef: nextCredentialRef },
      ]) {
        const denied = await metadataApp.inject({
          method: 'PATCH',
          url: path,
          headers: mutateHeaders,
          payload: invalid,
        });
        expect([400, 403, 412]).toContain(denied.statusCode);
        expect(await effects()).toEqual(afterCreate);
      }
      const invoke = () =>
        metadataApp.inject({
          method: 'PATCH',
          url: path,
          headers: mutateHeaders,
          payload: updateBody,
        });
      const [actual, duplicate] = await Promise.all([invoke(), invoke()]);
      expect(actual.statusCode, actual.body).toBe(202);
      expect(duplicate.statusCode, duplicate.body).toBe(202);
      expect(duplicate.json()).toEqual(actual.json());
      updated = actual.json<OperationRecord>();
      expect(await signedRepository.update(updateContext, updateBody)).toEqual(updated);
    } finally {
      await metadataApp.close();
    }
    expect(updated).toMatchObject({ state: 'SUCCEEDED', truthState: 'SUCCESS', revision: '2' });
    // The original public PATCH and consumed step-up are the cancellation cause.
    // Read it through a fresh scoped runtime connection; no business state is seeded.
    const causeSelector = {
      participantId,
      privacyDomainId,
      causeOperationId: updated.operationId,
      endpointId: resourceId,
      endpointRevision: '1',
    };
    const readCause = async (value = causeSelector) => {
      const readback = new Pool({ connectionString: urls.runtime, max: 1 });
      try {
        return await runScopedTransaction(
          readback,
          { participantId, privacyDomainId, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
          id,
          async (connection) => {
            await lockEvidenceLifecycle(connection, participantId, privacyDomainId);
            return readNotificationDeliveryCancellationCause(connection, value);
          },
        );
      } finally {
        await readback.end();
      }
    };
    const originalCause = await readCause();
    expect(originalCause).toMatchObject({
      operationId: updated.operationId,
      endpointId: resourceId,
      endpointRevision: '1',
      successorRevision: '2',
    });
    expect(await readCause()).toEqual(originalCause);
    for (const patch of [
      { privacyDomainId: id() },
      { causeOperationId: id() },
      { endpointRevision: '2' },
    ])
      await expect(readCause({ ...causeSelector, ...patch })).rejects.toThrow();
    for (const table of [
      'notification_delivery_cancellation',
      'notification_delivery_outcome',
      'notification_delivery_observation',
    ]) {
      const privileges = await runtime.query(
        `select has_table_privilege(current_user,$1,'UPDATE') can_update,
          has_table_privilege(current_user,$1,'DELETE') can_delete,
          relrowsecurity and relforcerowsecurity protected from pg_class where oid=$1::regclass`,
        [`control.${table}`],
      );
      expect(privileges.rows).toEqual([{ can_update: false, can_delete: false, protected: true }]);
      await expect(
        runtime.query(`update control.${table} set operation_id=operation_id where false`),
      ).rejects.toThrow();
      await expect(runtime.query(`delete from control.${table} where false`)).rejects.toThrow();
    }
    const changed = await actual();
    expect(changed).toMatchObject({
      state: 'DISABLED',
      revision: '2',
      verification_id: null,
      credential_ref: nextCredentialRef,
      destination_ref: nextDestination,
      candidate_digest: updateBody.replacementDigest,
    });
    expect(await effects()).toEqual({ ...afterPreparation, receipts: 2, outbox: 2, operations: 2 });
    const receipts = async () =>
      (
        await admin.query(
          `select receipt_id,operation_id,receipt_cbor,cose_sign1,before_state_preimage,after_state_preimage
      from control.audit_occurrence where participant_id=$1 and privacy_domain_id=$2 and aggregate_id=$3 order by after_revision`,
          [participantId, privacyDomainId, resourceId],
        )
      ).rows;
    const retainedReceipts = await receipts();
    expect(retainedReceipts).toHaveLength(2);
    for (const [index, row] of retainedReceipts.entries()) {
      expect(verifyReceiptCose(signing.publicKey, row.receipt_cbor, row.cose_sign1)).toBe(true);
      expect(decodeAdmittedReceipt(row.receipt_cbor)).toMatchObject({
        aggregateId: resourceId,
        before: { existence: index === 0 ? 0 : 1, revision: BigInt(index) },
        after: { existence: 1, revision: BigInt(index + 1) },
      });
      const outbox = await admin.query(
        `select count(*)::int n from control.outbox_event e join control.receipt_signing_attempt a
        on a.attempt_id=e.receipt_id and a.participant_id=e.participant_id where e.participant_id=$1 and e.privacy_domain_id=$2
         and a.operation_id=$3 and a.attempt_id=$4 and a.payload_cbor=$5`,
        [participantId, privacyDomainId, row.operation_id, row.receipt_id, row.receipt_cbor],
      );
      expect(outbox.rows[0].n).toBe(1);
    }
    const readAction = 'ACT-NOTIFICATION_ENDPOINTS_READ_RESOURCE-V1';
    const readProof = await authorizer.authorize({
      sessionToken: maker.sessionToken,
      participantId,
      privacyDomainId,
      actionIntentId: readAction,
      resourceId,
      candidateDigest: digest({ actionIntentId: readAction, resourceId }),
      makerCheckerRequired: false,
      stepUpRequired: false,
    });
    const reloaded = new NotificationEndpointRepository(
      runtime,
      verifier,
      signing.evidence,
      new NotificationEndpointVerificationState(runtime, verifier),
    );
    const publicRead = await reloaded.get({
      authorization: readProof,
      actionIntentId: readAction,
      resourceType: 'notification-endpoints',
      resourceId,
    });
    expect(publicRead).toMatchObject({
      state: 'DISABLED',
      revision: '2',
      destinationRef: nextDestination,
    });
    expect(Object.keys(publicRead).sort()).toEqual(
      [
        'notificationEndpointId',
        'participantId',
        'channel',
        'destinationRef',
        'state',
        'arbitraryEgress',
        'revision',
        'createdAt',
        'updatedAt',
      ].sort(),
    );
    expect(await reloaded.create(createContext, body)).toEqual(created);
    expect(await reloaded.update(updateContext, updateBody)).toEqual(updated);
    await fixture.restartConfiguration(signing.evidence);
    expect((await fixture.read(`operations/${created.operationId}`)).body).toEqual(created);
    expect((await fixture.read(`operations/${updated.operationId}`)).body).toEqual(updated);
    expect(await receipts()).toEqual(retainedReceipts);
    const completedEffects = await effects();
    // VERIFY must not infer PROVED from creation, replacement, valid TLS metadata,
    // or a caller-supplied digest. No delivery or attempt is seeded to open it.
    if (!created.resourceRef) throw new Error('Created endpoint must have a resource reference');
    const verifyAction = 'ACT-NOTIFICATION_UPDATE_VERIFY-V1';
    const verifyBody = {
      actionIntentId: verifyAction,
      actionIntentDigest: client.actionDigests.get(verifyAction)!,
      targetRef: created.resourceRef,
      expectedRevision: '2',
      inputDigest: digest({
        targetRef: created.resourceRef,
        expectedRevision: '2',
        transition: 'VERIFY',
      }),
      reason: 'Verify current exact replacement binding.',
    };
    const verifyInput = {
      ...input,
      actionIntentId: verifyAction,
      actionIntentDigest: verifyBody.actionIntentDigest,
      catalogOperationId: operations[2]!,
      idempotencyKey: `notification-endpoint-verify-${id()}`,
      expectedRevision: '2',
      candidateDigest: digest(verifyBody),
      stepUpRequired: false,
      csrfToken: await client.csrf(maker, verifyAction, fixture.service.identityUrl),
    };
    const verifyProof = await authorizer.authorize(verifyInput);
    if (verifyProof.evidenceKind !== 'IDENTITY_RUNTIME')
      throw new Error('VERIFY requires ordinary real runtime authorization');
    const verifyContext: MutationContext = {
      ...context,
      authorization: verifyProof,
      actionIntentId: verifyAction,
      actionIntentDigest: verifyBody.actionIntentDigest,
      catalogOperationId: verifyInput.catalogOperationId,
      idempotencyKey: verifyInput.idempotencyKey,
      resourceType: 'notification-endpoint',
      operationClass: 'UPDATE',
      expectedRevision: '2',
      candidate: verifyBody,
    };
    await expect(
      new NotificationEndpointVerificationState(runtime, verifier).prepare(verifyContext),
    ).rejects.toThrow('PC-INTEGRATION-5001');
    await expect(reloaded.verify(verifyContext, verifyBody)).rejects.toThrow('PC-DATA-6007');
    expect(await effects()).toEqual(completedEffects);
    // Privileged installation withdrawal is terminal; it grants no endpoint effect.
    await admin.query(
      "update control.installed_notification_channel set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3",
      [participantId, privacyDomainId, credentialRef],
    );
    await expect(selected()).rejects.toThrow('PC-DATA-6007');
    await expect(install(installation)).rejects.toThrow('PC-DATA-6007');
    await expect(
      admin.query(
        "update control.installed_notification_channel set state='ACTIVE' where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3",
        [participantId, privacyDomainId, credentialRef],
      ),
    ).rejects.toThrow('DATA-6020-NOTIFICATION-INSTALLATION-IMMUTABLE');
    expect(await effects()).toEqual(completedEffects);
    const stalePool = new Pool({
      connectionString: urls.runtime,
      max: 1,
      connectionTimeoutMillis: 5000,
    });
    const stale = await stalePool.connect();
    try {
      await stale.query('begin isolation level serializable');
      await stale.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
        participantId,
        privacyDomainId,
        id(),
        verifyAction,
      ]);
      const staleRead = () =>
        stale.query(
          'select state from control.installed_notification_channel where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3',
          [participantId, privacyDomainId, nextCredentialRef],
        );
      expect((await staleRead()).rows[0].state).toBe('ACTIVE');
      await admin.query(
        "update control.installed_notification_channel set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3",
        [participantId, privacyDomainId, nextCredentialRef],
      );
      expect((await staleRead()).rows[0].state).toBe('ACTIVE');
      // The supported owner starts fresh under its own retained fence; the stale
      // observation cannot authorize an effect or preserve an ACTIVE admission.
      await expect(reloaded.verify(verifyContext, verifyBody)).rejects.toThrow('PC-DATA-6007');
      expect(await effects()).toEqual(completedEffects);
      await assertInstallationFenceReleased();
    } finally {
      await stale.query('rollback');
      stale.release();
      await stalePool.end();
    }
    await expect(
      new NotificationEndpointVerificationState(runtime, verifier).prepare(verifyContext),
    ).rejects.toThrow('PC-DATA-6007');
    expect(await effects()).toEqual(completedEffects);
    const routedRead = await fixture.read(`notification-endpoints/${created.resourceRef}`);
    if (routedRead.status === 404 || routedRead.status >= 500)
      blocked(
        'canonical ConfigurationApiOptions.notificationEndpointOwners and registerResourceRoutes endpoint repository/read routes',
      );
    expect(routedRead).toMatchObject({ status: 200, body: publicRead });
    await joinedNotificationVerification({
      admin,
      runtimeUrl: urls.runtime,
      fixture,
      signing,
      peer: tls,
      installation,
      authorizer,
      verifier,
      baseContext: context,
    });
  } finally {
    await app?.close();
    await fixture?.close();
    signing?.close();
    signingKey?.fill(0);
    await runtime.end();
    await admin.end();
    await tls?.close();
  }
}, 240000);

/** One admitted setup; independent endpoint/credential/intent identities per
 * case. Only the external gateway and physical test provider are simulated.
 * Existing owner cases remain, followed by the registered public VERIFY route. */
async function joinedNotificationVerification({
  admin,
  runtimeUrl,
  fixture,
  signing,
  peer,
  installation,
  authorizer,
  verifier,
  baseContext,
}: {
  admin: Pool;
  runtimeUrl: string;
  fixture: Awaited<ReturnType<typeof contractAdministrationFixture>>;
  signing: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>>;
  peer: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>;
  installation: NotificationChannelInstallation;
  authorizer: ReturnType<typeof createLocalConfigurationAuthorizer>;
  verifier: ReturnType<typeof createLocalIdentityRuntimeVerifier>;
  baseContext: MutationContext;
}) {
  // Recipient retains its real SQL transaction through the callback. Sharing
  // the metadata pool's single slot with dispatch would starve the callback.
  // Added caps: recipient 1 + verification 2; concurrent Atomic mutations may
  // each add their existing bounded single business connection (maximum 2).
  const recipientPool = new Pool({
    connectionString: runtimeUrl,
    max: 1,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    idle_in_transaction_session_timeout: 30000,
  });
  const verificationPool = new Pool({
    connectionString: runtimeUrl,
    max: 2,
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    idle_in_transaction_session_timeout: 30000,
  });
  const { participantId, privacyDomainId } = installation.credential;
  const { client, maker } = fixture.governance;
  const kernel = new IdentityKernel(new PostgresIdentityRepository(recipientPool, systemClock));
  const recipient = buildLocalWorkloadMtlsService(recipientPool, kernel, peer.server);
  type Provider = ReturnType<typeof createTestNotificationCredentialProvider>;
  type Gateway = {
    port: number;
    setFault(value: 'NORMAL' | 'LOST_ACK'): void;
    setVerificationOutcome(value: 'PROVED' | 'REJECTED'): void;
    verificationStats(): { calls: number; receipts: number };
    close(): Promise<void>;
  };
  const gatewayUrl = new URL('../local-runtime/notification-gateway-fixture.mjs', import.meta.url);
  const { createNotificationGatewayFixture } = (await import(gatewayUrl.href)) as {
    createNotificationGatewayFixture(options: {
      tls: { ca: Buffer; cert: Buffer; key: Buffer };
      installed: ReturnType<typeof verifyInstalledNotificationChannel>;
      signerPrivateKey: Buffer;
      signerSpki: Buffer;
      clientSpkiDigest: string;
      journalPath: string;
      port: number;
      verification: {
        installed: ReturnType<typeof verifyInstalledNotificationVerification>;
        signerPrivateKey: Buffer;
        signerSpki: Buffer;
        observeRequest(
          challenge: NotificationVerificationChallenge,
          signal: AbortSignal,
        ): Promise<void>;
      };
    }): Promise<Gateway>;
  };
  let pending:
    | {
        provider: Provider;
        use(lease: NotificationCredentialLease): Promise<unknown>;
        result?: unknown;
        failed: boolean;
        error?: unknown;
      }
    | undefined;
  let publicCall:
    | {
        run(socket: TLSSocket): Promise<void>;
        failed: boolean;
        error?: unknown;
      }
    | undefined;
  recipient.post('/test/notification-joined-recipient', async (req, reply) => {
    if (publicCall) {
      const selected = publicCall;
      try {
        // Test root only: retain the real inbound workload peer while a separate
        // public HTTP listener executes browser requests. The workflow itself
        // authenticates this socket through the real recipient/Identity owner.
        await selected.run(req.raw.socket as TLSSocket);
        return { ok: true };
      } catch (error) {
        selected.failed = true;
        selected.error = error;
        return reply.code(500).send({ code: 'TEST_PUBLIC_NOTIFICATION_FAILED' });
      }
    }
    const call = pending;
    if (!call) return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
    try {
      call.result = await withNotificationSecretRecipient(
        recipientPool,
        kernel,
        req.raw.socket as TLSSocket,
        req.body as NotificationSecretRequest,
        call.provider,
        async (lease) => {
          try {
            return await call.use(lease);
          } catch (error) {
            call.failed = true;
            call.error = error;
            throw error;
          }
        },
      );
      return { ok: true };
    } catch (error) {
      if (!call.failed) {
        call.failed = true;
        call.error = error;
      }
      return reply.code(403).send({ code: 'OPS_SECRET_UNRESOLVED' });
    }
  });
  let outbound: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>> | undefined;
  let credentialBytes: Buffer | undefined;
  let root: string | undefined;
  let address = '';
  const providers: Provider[] = [];
  const keys: Buffer[] = [];
  const gateways = new Set<Gateway>();
  const failures: unknown[] = [];
  const cleanup = async (action: () => unknown | Promise<unknown>) => {
    try {
      await action();
      return true;
    } catch (error) {
      failures.push(error);
      return false;
    }
  };
  const key = () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const privateKey = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
    keys.push(privateKey);
    return { privateKey, spki: pair.publicKey.export({ format: 'der', type: 'spki' }) };
  };
  const bounded = <T>(work: Promise<T>, milliseconds: number, label: string): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    return Promise.race([
      work,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(label)), milliseconds);
      }),
    ]).finally(() => clearTimeout(timer));
  };
  const withLease = async <T>(
    credential: NotificationChannelInstallation['credential'],
    provider: Provider,
    use: (lease: NotificationCredentialLease) => Promise<T>,
    requestChange: Partial<NotificationSecretRequest> = {},
  ): Promise<T> => {
    expect(pending).toBeUndefined();
    const call = { provider, use, failed: false } as NonNullable<typeof pending>;
    pending = call;
    try {
      const result = await peer.post(`${address}/test/notification-joined-recipient`, {
        participantId,
        privacyDomainId,
        credentialRef: credential.credentialRef,
        reference: credential.reference,
        version: credential.version,
        epoch: credential.epoch,
        ...requestChange,
      });
      if (call.failed) throw call.error;
      expect(result).toMatchObject({ status: 200, body: { ok: true } });
      return call.result as T;
    } finally {
      pending = undefined;
    }
  };
  const authorize = async (
    command: 'CREATE' | 'VERIFY',
    endpointId: string,
    body: Record<string, unknown> & { actionIntentId: string; actionIntentDigest: string },
    idempotencyKey: string,
  ): Promise<MutationContext> => {
    if (command === 'CREATE')
      await client.stepUp(maker, body.actionIntentId, endpointId, digest(body));
    const proof = await authorizer.authorize({
      sessionToken: maker.sessionToken,
      participantId,
      privacyDomainId,
      resourceId: endpointId,
      catalogOperationId: `CFG-OP-${command}-NOTIFICATION-ENDPOINT`,
      actionIntentId: body.actionIntentId,
      actionIntentDigest: body.actionIntentDigest,
      idempotencyKey,
      candidateDigest: digest(body),
      expectedRevision: command === 'CREATE' ? '0' : '1',
      makerCheckerRequired: false,
      stepUpRequired: command === 'CREATE',
      origin: fixture.service.identityUrl,
      host: new URL(fixture.service.identityUrl).host,
      csrfToken: await client.csrf(maker, body.actionIntentId, fixture.service.identityUrl),
    });
    expect(proof.evidenceKind).toBe(
      command === 'CREATE' ? 'IDENTITY_RUNTIME_STEP_UP' : 'IDENTITY_RUNTIME',
    );
    if (
      proof.evidenceKind !== 'IDENTITY_RUNTIME_STEP_UP' &&
      proof.evidenceKind !== 'IDENTITY_RUNTIME'
    )
      blocked('notification endpoint mutation authorization proof');
    return {
      ...baseContext,
      authorization: proof,
      actionIntentId: body.actionIntentId,
      actionIntentDigest: body.actionIntentDigest,
      catalogOperationId: `CFG-OP-${command}-NOTIFICATION-ENDPOINT`,
      idempotencyKey,
      resourceId: endpointId,
      resourceType: command === 'CREATE' ? 'notification-endpoints' : 'notification-endpoint',
      operationClass: command === 'CREATE' ? 'CREATE' : 'UPDATE',
      expectedRevision: command === 'CREATE' ? '0' : '1',
      candidate: body,
    };
  };
  try {
    root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT ?? tmpdir(), 'notification-joined-'));
    outbound = await runtimeSnapshotTlsFixture('urn:openpc:test:notification-joined-gateway');
    const privateDer = createPrivateKey(outbound.privateKey).export({
      format: 'der',
      type: 'pkcs8',
    });
    try {
      credentialBytes = encodeCbor(
        new Map<number, CborValue>([
          [0, notificationCredentialEncoding],
          [1, privateDer],
          [2, [outbound.parsed.raw, new X509Certificate(outbound.server.ca).raw]],
          [3, [new X509Certificate(outbound.server.ca).raw]],
        ]),
      );
    } finally {
      privateDer.fill(0);
    }
    expect(outbound.parsed.keyUsage).toContain('1.3.6.1.5.5.7.3.2');
    expect(decodeNotificationCredentialMaterial(credentialBytes).fingerprint).toBe(
      sha256(credentialBytes),
    );
    address = await recipient.listen({ host: '127.0.0.1', port: 0 });
    const stateOwner = () => new NotificationEndpointVerificationState(verificationPool, verifier);
    const repository = () =>
      new NotificationEndpointRepository(
        verificationPool,
        verifier,
        signing.evidence,
        stateOwner(),
      );
    const scenario = async (name: string, requestTimeoutMs = 30000) => {
      const endpointId = id(),
        credentialRef = `urn:openpc:resource:${id()}`,
        destinationRef = `urn:openpc:resource:${id()}`;
      const reservation = createServer();
      await new Promise<void>((resolve, reject) => {
        reservation.once('error', reject);
        reservation.listen(0, '127.0.0.1', resolve);
      });
      const reserved = reservation.address();
      if (!reserved || typeof reserved === 'string') throw new Error('Gateway port missing');
      const port = reserved.port;
      await new Promise<void>((resolve, reject) =>
        reservation.close((error) => (error ? reject(error) : resolve())),
      );
      const issuer = key(),
        gatewaySigner = key(),
        verificationSigner = key(),
        now = Date.now();
      const credential = {
        ...installation.credential,
        credentialRef,
        destinationRef,
        reference: `secret://local/notification-joined-${endpointId}#1`,
        fingerprint: sha256(credentialBytes!),
        validFromMs: now - 1000,
        validUntilMs: now + 3600000,
      };
      const transport = {
        ...installation.channelSigned.transport,
        destinationRef,
        credentialRef,
        endpoint: `https://127.0.0.1:${port}/`,
        serverSpkiDigest: sha256(
          new X509Certificate(outbound!.server.certificate).publicKey.export({
            format: 'der',
            type: 'spki',
          }),
        ),
        requestTimeoutMs,
      };
      const claims = {
        environmentId: installation.channelTrust.environmentId,
        participantId,
        privacyDomainId,
        profileId: id(),
        revision: '1',
        validFromMs: now - 1000,
        validUntilMs: now + 3600000,
        transportProfileDigest: sha256(transport),
        receiptSignerSpki: gatewaySigner.spki.toString('hex'),
        issuerKeyId: evidenceKeyId(issuer.spki),
      };
      const signedChannel = signNotificationClaim(
        'NotificationChannelProfileV1',
        issuer.privateKey,
        issuer.spki,
        claims,
      );
      const channelTrust = {
        ...installation.channelTrust,
        signedProfileDigest: sha256(signedChannel.cose),
        issuerSpkiHex: issuer.spki.toString('hex'),
      };
      const channelSigned = {
        transport,
        payloadHex: signedChannel.payload.toString('hex'),
        coseHex: signedChannel.cose.toString('hex'),
      };
      const channel = verifyInstalledNotificationChannel(channelTrust, channelSigned);
      const profile = signNotificationClaim(
        'NotificationVerificationProfileV1',
        issuer.privateKey,
        issuer.spki,
        {
          environmentId: claims.environmentId,
          participantId,
          privacyDomainId,
          profileId: id(),
          revision: '1',
          validFromMs: now - 1000,
          validUntilMs: now + 3600000,
          signedChannelProfileDigest: channel.signedProfileDigest,
          credentialBindingDigest: sha256(credential),
          verificationSignerSpki: verificationSigner.spki.toString('hex'),
          issuerKeyId: evidenceKeyId(issuer.spki),
        },
      );
      const verification = {
        trust: { ...channelTrust, signedProfileDigest: sha256(profile.cose) },
        signed: {
          payloadHex: profile.payload.toString('hex'),
          coseHex: profile.cose.toString('hex'),
        },
      };
      const installed = verifyInstalledNotificationVerification(
        verification.trust,
        verification.signed,
        channelTrust,
        channelSigned,
      );
      const connection = await admin.connect();
      try {
        await connection.query('begin');
        await installInitialNotificationChannel(connection, {
          ...installation,
          credential,
          channelTrust,
          channelSigned,
          verification,
          admissionReference: `Joined verification initial trust: ${name}`,
        });
        await connection.query('commit');
      } catch (error) {
        await connection.query('rollback');
        throw error;
      } finally {
        connection.release();
      }
      const provider = createTestNotificationCredentialProvider(credential, credentialBytes!);
      providers.push(provider);
      const readAttempt = async (attemptId: string) => {
        const result = await admin.query(
          `select attempt_id,state,challenge_bytes,response_bytes,verified_at_ms::text,receipt_digest,attached_operation_id,
           (select count(*)::int from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3) attempts
           from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 and attempt_id=$4`,
          [participantId, privacyDomainId, endpointId, attemptId],
        );
        expect(result.rowCount).toBe(1);
        return result.rows[0]!;
      };
      const effects = async () =>
        (
          await admin.query(
            `select e.state,e.revision::text,e.verification_id,
         (select count(*)::int from control.notification_endpoint_verification v where v.participant_id=e.participant_id and v.endpoint_id=e.endpoint_id) verifications,
         (select count(*)::int from control.audit_occurrence a where a.participant_id=e.participant_id and a.aggregate_id=e.endpoint_id) receipts,
         (select count(*)::int from control.outbox_event o where o.participant_id=e.participant_id and o.aggregate_id=e.endpoint_id) outbox,
         (select count(*)::int from control.idempotency_record i where i.participant_id=e.participant_id and i.catalog_operation_id=any($4::text[])) operations
         from control.notification_endpoint e where e.participant_id=$1 and e.privacy_domain_id=$2 and e.endpoint_id=$3`,
            [participantId, privacyDomainId, endpointId, operations],
          )
        ).rows[0];
      let barrier: ((signal: AbortSignal) => Promise<void>) | undefined;
      let observerFailed = false,
        observerError: unknown;
      const observations: string[] = [];
      const gatewayOptions = {
        tls: {
          ca: outbound!.server.ca,
          cert: outbound!.server.certificate,
          key: outbound!.server.privateKey,
        },
        installed: channel,
        signerPrivateKey: gatewaySigner.privateKey,
        signerSpki: gatewaySigner.spki,
        clientSpkiDigest: sha256(
          outbound!.parsed.publicKey.export({ format: 'der', type: 'spki' }),
        ),
        journalPath: join(root!, `${endpointId}.jsonl`),
        port,
        verification: {
          installed,
          signerPrivateKey: verificationSigner.privateKey,
          signerSpki: verificationSigner.spki,
          observeRequest: async (
            challenge: NotificationVerificationChallenge,
            signal: AbortSignal,
          ) => {
            try {
              // A separate connection observes the actual committed state before
              // the external gateway signs or sends any response.
              const row = await readAttempt(challenge.challengeId);
              expect(row.state).toBe('DISPATCHED');
              expect(row.response_bytes).toBeNull();
              expect(row.attached_operation_id).toBeNull();
              expect(parseNotificationVerificationRequest(row.challenge_bytes)).toEqual(challenge);
              expect(await effects()).toMatchObject({
                state: 'DISABLED',
                revision: '1',
                verification_id: null,
                verifications: 0,
                receipts: 1,
                outbox: 1,
              });
              observations.push(challenge.challengeId);
              await barrier?.(signal);
            } catch (error) {
              observerFailed = true;
              observerError = error;
              throw error;
            }
          },
        },
      };
      let gateway = await createNotificationGatewayFixture(gatewayOptions);
      gateways.add(gateway);
      const createAction = 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1';
      const createBody = {
        actionIntentId: createAction,
        actionIntentDigest: client.actionDigests.get(createAction)!,
        participantId: `urn:openpc:participant:${participantId}`,
        channel: 'WEBHOOK' as const,
        destinationRef,
        arbitraryEgress: false as const,
        reason: `Joined verification ${name}`,
      };
      const createContext = await authorize(
        'CREATE',
        endpointId,
        createBody,
        `joined-create-${endpointId}`,
      );
      const created = await repository().create(createContext, createBody);
      expect(created).toMatchObject({ state: 'SUCCEEDED', revision: '1' });
      const verifyAction = 'ACT-NOTIFICATION_UPDATE_VERIFY-V1';
      const body = {
        actionIntentId: verifyAction,
        actionIntentDigest: client.actionDigests.get(verifyAction)!,
        targetRef: created.resourceRef!,
        expectedRevision: '1',
        inputDigest: digest({
          targetRef: created.resourceRef,
          expectedRevision: '1',
          transition: 'VERIFY',
        }),
        reason: `Joined verification ${name}`,
      };
      const intent = `joined-verify-${endpointId}`;
      let context = await authorize('VERIFY', endpointId, body, intent);
      const owner = stateOwner();
      return {
        endpointId,
        credential,
        provider,
        body,
        owner,
        readAttempt,
        effects,
        observations,
        intent,
        context: () => context,
        gateway: () => gateway,
        copiedContext: () => authorize('VERIFY', endpointId, body, `${intent}-copied`),
        changedInput: async () => {
          const changed = {
            ...body,
            inputDigest: digest({ original: body.inputDigest, altered: true }),
          };
          return { body: changed, context: await authorize('VERIFY', endpointId, changed, intent) };
        },
        refresh: async () => {
          context = await authorize('VERIFY', endpointId, body, intent);
          return context;
        },
        barrier: (value: typeof barrier) => {
          barrier = value;
        },
        lease: <T>(
          use: (lease: NotificationCredentialLease) => Promise<T>,
          change: Partial<NotificationSecretRequest> = {},
        ) => withLease(credential, provider, use, change),
        assertObserver: () => {
          if (observerFailed) throw observerError;
        },
        authenticate: (row: Awaited<ReturnType<typeof readAttempt>>) =>
          verifyNotificationVerificationResponse(
            installed,
            parseNotificationVerificationRequest(row.challenge_bytes),
            row.response_bytes,
            Number(row.verified_at_ms),
          ),
        restartGateway: async () => {
          await gateway.close();
          gateways.delete(gateway);
          gateway = await createNotificationGatewayFixture(gatewayOptions);
          gateways.add(gateway);
        },
      };
    };

    type Scenario = Awaited<ReturnType<typeof scenario>>;
    let publicRootUnsettled = false;
    const publicApplication = async (
      test: Scenario,
      source: TLSSocket | ReturnType<typeof createNotificationVerificationRuntime>,
    ) => {
      const app = Fastify({ logger: false, trustProxy: false });
      let discardResponse = false;
      app.addHook('onSend', async (request, reply, payload) => {
        if (discardResponse && request.method === 'POST' && reply.statusCode === 202) {
          discardResponse = false;
          // The actual route has already committed. Lose only the HTTP response,
          // never the source effect or the original idempotency identity.
          reply.raw.destroy();
        }
        return payload;
      });
      const workflow =
        source instanceof TLSSocket
          ? new NotificationEndpointVerificationWorkflow({
              pool: verificationPool,
              recipientPool,
              kernel,
              identityRuntimeVerifier: verifier,
              businessEvidence: signing.evidence,
              workloadPeer: source,
              credentialProvider: test.provider,
              timeoutMs: 10000,
            })
          : source.workflow;
      registerConfigurationRoutes(app, {
        pool: verificationPool,
        authorizer,
        identityRuntimeVerifier: verifier,
        businessEvidence: signing.evidence,
        notificationEndpointOwners: source instanceof TLSSocket ? stateOwner() : source.owners,
        notificationEndpointVerification: workflow,
      });
      let url: string;
      try {
        url = await app.listen({ host: '127.0.0.1', port: 0 });
      } catch (error) {
        await app.close();
        throw error;
      }
      return {
        close: () => app.close(),
        discardNextResponse: () => {
          discardResponse = true;
        },
        async verify(
          payload: Record<string, unknown> = test.body,
          changes: Record<string, string> = {},
        ) {
          return client.request(
            `${url}/api/v1/notification-endpoints/${test.body.targetRef}/verify`,
            maker,
            payload,
            {
              'OpenPC-API-Version': '1',
              'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
              'X-Request-ID': id(),
              'X-Correlation-ID': id(),
              'Idempotency-Key': test.intent,
              'OpenPC-Action-Intent-Digest': test.body.actionIntentDigest,
              'If-Match': `"${digest({ resourceId: test.endpointId, revision: '1' })}"`,
              'X-CSRF-Token': await client.csrf(maker, test.body.actionIntentId, url),
              ...changes,
            },
          );
        },
        async read() {
          const result = await fetch(
            `${url}/api/v1/notification-endpoints/${test.body.targetRef}`,
            {
              headers: {
                'Cookie': `__Host-openpc_session=${maker.sessionToken}`,
                'OpenPC-API-Version': '1',
                'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
                'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
                'X-Request-ID': id(),
                'X-Correlation-ID': id(),
              },
              signal: AbortSignal.timeout(10000),
            },
          );
          return { status: result.status, body: (await result.json()) as Record<string, unknown> };
        },
      };
    };
    const withPublic = async (
      test: Scenario,
      run: (http: Awaited<ReturnType<typeof publicApplication>>) => Promise<void>,
    ) => {
      expect(publicCall).toBeUndefined();
      expect(pending).toBeUndefined();
      let started = false,
        finish!: () => void;
      const finished = new Promise<void>((resolve) => {
        finish = resolve;
      });
      const selected: NonNullable<typeof publicCall> = {
        failed: false,
        run: async (socket) => {
          started = true;
          try {
            const http = await publicApplication(test, socket);
            try {
              await run(http);
            } finally {
              await cleanup(() => http.close());
            }
          } finally {
            finish();
          }
        },
      };
      publicCall = selected;
      try {
        const status = await new Promise<number>((resolve, reject) => {
          const call = httpsRequest(
            `${address}/test/notification-joined-recipient`,
            {
              method: 'POST',
              ca: peer.server.ca,
              cert: peer.certificate,
              key: peer.privateKey,
              minVersion: 'TLSv1.3',
              maxVersion: 'TLSv1.3',
              signal: AbortSignal.timeout(60000),
              headers: { 'content-type': 'application/json' },
            },
            (response) => {
              response.resume();
              response.on('error', reject);
              response.on('end', () => resolve(response.statusCode ?? 0));
            },
          );
          call.on('error', reject);
          call.end('{}');
        });
        if (selected.failed) throw selected.error;
        expect(status).toBe(200);
      } catch (error) {
        // A disconnected controlling TLS call is not permission to overlap a
        // still-running public case with the next mutable fixture scenario.
        if (started) {
          try {
            await bounded(finished, 15000, 'Public notification root cleanup did not settle');
          } catch (cleanupError) {
            publicRootUnsettled = true;
            throw new AggregateError(
              [error, cleanupError],
              'Public notification case and cleanup failed',
            );
          }
        }
        throw error;
      } finally {
        publicCall = undefined;
      }
    };
    // New runtime is exercised inside this same real owner suite, not a parallel
    // test harness. Three additional capped connections exist only for this case.
    const withRuntime = async (
      test: Scenario,
      run: (
        http: Awaited<ReturnType<typeof publicApplication>>,
        disconnect: () => void,
      ) => Promise<void>,
      connectPeer = true,
    ) => {
      const runtime = createNotificationVerificationRuntime({
        database: { connectionString: runtimeUrl },
        tls: peer.server,
        identityRuntimeVerifier: verifier,
        businessEvidence: signing.evidence,
        credentialProvider: test.provider,
        timeoutMs: 10000,
      });
      let socket: TLSSocket | undefined;
      let http: Awaited<ReturnType<typeof publicApplication>> | undefined;
      try {
        const address = await runtime.start({ host: '127.0.0.1', port: 0 });
        if (connectPeer) {
          socket = tlsConnect({
            host: '127.0.0.1',
            port: address.port,
            ca: peer.server.ca,
            cert: peer.certificate,
            key: peer.privateKey,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
          });
          socket.on('error', () => {});
          await bounded(
            new Promise<void>((resolve, reject) => {
              socket!.once('secureConnect', resolve);
              socket!.once('error', reject);
            }),
            5000,
            'Actual workload TLS connection failed',
          );
          await expect
            .poll(
              async () =>
                runtime.preflight(test.credential).then(
                  () => true,
                  () => false,
                ),
              { timeout: 5000 },
            )
            .toBe(true);
        }
        http = await publicApplication(test, runtime);
        await run(http, () => socket?.destroy());
      } finally {
        socket?.destroy();
        if (http) await cleanup(() => http!.close());
        await cleanup(() => runtime.close());
      }
    };
    const onlyAttempt = async (test: Scenario) => {
      const result = await admin.query<{ attempt_id: string }>(
        'select attempt_id from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3',
        [participantId, privacyDomainId, test.endpointId],
      );
      expect(result.rowCount).toBe(1);
      return test.readAttempt(result.rows[0]!.attempt_id);
    };
    const noPublicEffect = async (
      test: Scenario,
      before: Awaited<ReturnType<Scenario['effects']>>,
    ) => {
      expect(await test.effects()).toEqual(before);
      expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 0 });
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.notification_verification_attempt where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3',
            [participantId, privacyDomainId, test.endpointId],
          )
        ).rows[0],
      ).toEqual({ n: 0 });
    };
    const assertPublicProblem = (
      result: { status: number; body: Record<string, unknown> },
      status: number,
      truthState: string,
    ) => {
      expect(result.status).toBe(status);
      expect(result.body).toMatchObject({ status, truthState, retryable: status === 503 });
      expect(Object.keys(result.body).sort()).toEqual(
        ['code', 'retryable', 'status', 'title', 'traceId', 'truthState', 'type'].sort(),
      );
    };
    const assertPublicAttachment = async (
      test: Scenario,
      operation: Record<string, unknown>,
      before: Awaited<ReturnType<Scenario['effects']>>,
    ) => {
      expect(operation).toMatchObject({
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        revision: '2',
        resourceRef: test.body.targetRef,
        idempotencyKey: test.intent,
      });
      expect(Object.keys(operation).sort()).toEqual(
        [
          'operationId',
          'resourceRef',
          'actionIntentId',
          'intentDigest',
          'idempotencyKey',
          'state',
          'truthState',
          'createdAt',
          'updatedAt',
          'revision',
        ].sort(),
      );
      const row = await onlyAttempt(test);
      expect(row).toMatchObject({
        state: 'ATTACHED',
        attached_operation_id: operation.operationId,
        attempts: 1,
      });
      expect(test.authenticate(row).receiptDigest).toBe(row.receipt_digest);
      test.assertObserver();
      expect(await test.effects()).toEqual({
        ...before,
        state: 'ACTIVE',
        revision: '2',
        verification_id: row.attempt_id,
        verifications: 1,
        receipts: 2,
        outbox: 2,
        operations: before.operations + 1,
      });
      const signed = await admin.query(
        `select a.receipt_cbor,a.cose_sign1,v.verification_id,
         (select count(*)::int from control.outbox_event o where o.participant_id=a.participant_id and o.receipt_id=a.receipt_id) outbox
         from control.audit_occurrence a join control.notification_endpoint_verification v on v.participant_id=a.participant_id and v.operation_id=a.operation_id
         where a.participant_id=$1 and a.aggregate_id=$2 and a.operation_id=$3`,
        [participantId, test.endpointId, operation.operationId],
      );
      expect(signed.rowCount).toBe(1);
      const receipt = signed.rows[0]!;
      expect(receipt).toMatchObject({ verification_id: row.attempt_id, outbox: 1 });
      expect(verifyReceiptCose(signing.publicKey, receipt.receipt_cbor, receipt.cose_sign1)).toBe(
        true,
      );
      expect(decodeAdmittedReceipt(receipt.receipt_cbor)).toMatchObject({
        aggregateId: test.endpointId,
        before: { revision: 1n },
        after: { revision: 2n },
      });
      return row;
    };

    const runScenario = async (
      name: string,
      timeoutMs: number,
      run: (value: Awaited<ReturnType<typeof scenario>>) => Promise<void>,
    ) => {
      const priorGateways = new Set(gateways),
        providerStart = providers.length;
      let active: Awaited<ReturnType<typeof scenario>> | undefined;
      try {
        if (publicRootUnsettled)
          blocked(`unsettled public root prevents safe scenario reuse: ${name}`);
        active = await scenario(name, timeoutMs);
        await run(active);
      } catch (error) {
        try {
          active?.assertObserver();
        } catch (cause) {
          failures.push(
            new Error(`Gateway committed-state observation failed: ${name}`, { cause }),
          );
        }
        failures.push(
          new Error(`Joined verification case failed; dependent checks BLOCKED: ${name}`, {
            cause: error,
          }),
        );
      } finally {
        signing.faults.mode = undefined;
        for (const gateway of gateways)
          if (!priorGateways.has(gateway)) {
            if (await cleanup(() => gateway.close())) gateways.delete(gateway);
          }
        for (const provider of providers.slice(providerStart))
          await cleanup(() => provider.close());
      }
    };
    const window = () => ({ timeoutMs: 5000, signal: new AbortController().signal });
    // Every case prepares fresh authority only after its stable provider/gateway,
    // initial trust and real disabled endpoint exist. No intermediate rows are seeded.
    // A failed prerequisite blocks its dependents; independent cases still run,
    // retaining the first failure and an aggregate nonzero result.
    await runScenario('positive rollback and one-use attachment', 30000, async (positive) => {
      const unchanged = await positive.effects();
      for (const change of [
        { version: '2' },
        { epoch: '2' },
        { privacyDomainId: id() },
        { credentialRef: `urn:openpc:resource:${id()}` },
      ]) {
        let entered = false;
        await expect(
          positive.lease(async () => {
            entered = true;
          }, change),
        ).rejects.toThrow();
        expect(entered).toBe(false);
        expect(positive.gateway().verificationStats()).toEqual({ calls: 0, receipts: 0 });
        expect(await positive.effects()).toEqual(unchanged);
      }
      const prepared = await positive.owner.prepare(await positive.refresh());
      expect(prepared.state).toBe('PREPARED');
      const initial = await positive.readAttempt(prepared.attemptId);
      expect(initial).toMatchObject({
        state: 'PREPARED',
        response_bytes: null,
        attached_operation_id: null,
        attempts: 1,
      });
      expect(await positive.owner.prepare(positive.context())).toEqual(prepared);
      expect(positive.gateway().verificationStats().calls).toBe(0);
      let observed!: () => void, resume!: () => void;
      const arrived = new Promise<void>((resolve) => {
        observed = resolve;
      });
      const resumed = new Promise<void>((resolve) => {
        resume = resolve;
      });
      positive.barrier(async (signal) => {
        observed();
        await Promise.race([
          resumed,
          new Promise<never>((_resolve, reject) => {
            if (signal.aborted) reject(new Error('Gateway observer aborted'));
            else
              signal.addEventListener(
                'abort',
                () => reject(new Error('Gateway observer aborted')),
                {
                  once: true,
                },
              );
          }),
        ]);
      });
      expect(
        await positive.lease(async (lease) => {
          const first = positive.owner.dispatch(
            positive.context(),
            prepared.attemptId,
            lease,
            window(),
          );
          // Attach rejection immediately; retain the original result until the barrier exits.
          const outcome = Promise.allSettled([first]);
          let failed = false,
            failure: unknown;
          try {
            await bounded(arrived, 5000, 'Gateway did not observe committed DISPATCHED');
            expect(
              await stateOwner().dispatch(positive.context(), prepared.attemptId, lease, window()),
            ).toBe('DISPATCHED');
          } catch (error) {
            failed = true;
            failure = error;
          } finally {
            resume();
          }
          const [result] = await outcome;
          if (failed) throw failure;
          if (result?.status !== 'fulfilled') throw result?.reason;
          return result.value;
        }),
      ).toBe('PROVED');
      positive.barrier(undefined);
      positive.assertObserver();
      expect(positive.observations).toEqual([prepared.attemptId]);
      const proved = await positive.readAttempt(prepared.attemptId);
      expect(proved.state).toBe('PROVED');
      expect(proved.challenge_bytes).toEqual(initial.challenge_bytes);
      expect(positive.authenticate(proved)).toMatchObject({
        receiptDigest: proved.receipt_digest,
        claims: { outcome: 'PROVED' },
      });
      expect(await positive.effects()).toEqual(unchanged);
      const copied = await positive.copiedContext();
      await expect(
        positive.lease((lease) =>
          stateOwner().dispatch(copied, prepared.attemptId, lease, window()),
        ),
      ).rejects.toThrow();
      await expect(repository().verify(copied, positive.body)).rejects.toThrow();
      expect(await positive.readAttempt(prepared.attemptId)).toEqual(proved);
      expect(await positive.effects()).toEqual(unchanged);
      const changedInput = await positive.changedInput();
      await expect(stateOwner().prepare(changedInput.context)).rejects.toThrow();
      await expect(repository().verify(changedInput.context, changedInput.body)).rejects.toThrow();
      await expect(
        positive.lease((lease) => stateOwner().dispatch(positive.context(), id(), lease, window())),
      ).rejects.toThrow();
      expect(await positive.readAttempt(prepared.attemptId)).toEqual(proved);
      expect(await positive.effects()).toEqual(unchanged);
      for (const fault of ['UNAVAILABLE', 'CORRUPT'] as const) {
        signing.faults.mode = fault;
        try {
          await expect(
            repository().verify(await positive.refresh(), positive.body),
          ).rejects.toThrow();
        } finally {
          signing.faults.mode = undefined;
        }
        expect(await positive.readAttempt(prepared.attemptId)).toEqual(proved);
        expect(await positive.effects()).toEqual(unchanged);
      }
      const faultName = `test_verify_rollback_${positive.endpointId.replaceAll('-', '')}`;
      await admin.query(`create function openpc.${faultName}() returns trigger language plpgsql as $$ begin
      if NEW.aggregate_type='notification-endpoint' and NEW.participant_id='${participantId}'::uuid and NEW.aggregate_id='${positive.endpointId}'::uuid
      then raise exception 'TEST_NOTIFICATION_VERIFY_OUTBOX'; end if; return NEW; end $$;
      create trigger ${faultName} before insert on control.outbox_event for each row execute function openpc.${faultName}()`);
      try {
        await expect(repository().verify(await positive.refresh(), positive.body)).rejects.toThrow(
          'TEST_NOTIFICATION_VERIFY_OUTBOX',
        );
      } finally {
        await admin.query(
          `drop trigger ${faultName} on control.outbox_event; drop function openpc.${faultName}()`,
        );
      }
      expect(await positive.readAttempt(prepared.attemptId)).toEqual(proved);
      expect(await positive.effects()).toEqual(unchanged);
      const finalContext = await positive.refresh(),
        callsBefore = signing.faults.calls;
      const [verified, duplicate] = await Promise.all([
        repository().verify(finalContext, positive.body),
        repository().verify(finalContext, positive.body),
      ]);
      expect(duplicate).toEqual(verified);
      expect(verified).toMatchObject({ state: 'SUCCEEDED', truthState: 'SUCCESS', revision: '2' });
      expect(signing.faults.calls).toBe(callsBefore + 1);
      const attached = await positive.readAttempt(prepared.attemptId);
      expect(attached).toMatchObject({
        state: 'ATTACHED',
        attached_operation_id: verified.operationId,
      });
      expect(attached.challenge_bytes).toEqual(proved.challenge_bytes);
      expect(attached.response_bytes).toEqual(proved.response_bytes);
      expect(attached.receipt_digest).toBe(proved.receipt_digest);
      expect(await positive.effects()).toEqual({
        ...unchanged,
        state: 'ACTIVE',
        revision: '2',
        verification_id: prepared.attemptId,
        verifications: 1,
        receipts: 2,
        outbox: 2,
        operations: unchanged.operations + 1,
      });
      const evidence = await admin.query(
        `select a.receipt_id,a.receipt_cbor,a.cose_sign1,v.operation_id,v.verification_id,
      (select count(*)::int from control.outbox_event o where o.participant_id=a.participant_id and o.receipt_id=a.receipt_id) outbox
      from control.audit_occurrence a join control.notification_endpoint_verification v on v.participant_id=a.participant_id and v.operation_id=a.operation_id
      where a.participant_id=$1 and a.aggregate_id=$2 and a.operation_id=$3`,
        [participantId, positive.endpointId, verified.operationId],
      );
      expect(evidence.rowCount).toBe(1);
      const receipt = evidence.rows[0]!;
      expect(receipt).toMatchObject({
        operation_id: verified.operationId,
        verification_id: prepared.attemptId,
        outbox: 1,
      });
      expect(verifyReceiptCose(signing.publicKey, receipt.receipt_cbor, receipt.cose_sign1)).toBe(
        true,
      );
      expect(decodeAdmittedReceipt(receipt.receipt_cbor)).toMatchObject({
        aggregateId: positive.endpointId,
        before: { revision: 1n },
        after: { revision: 2n },
      });
      expect(positive.gateway().verificationStats()).toEqual({ calls: 1, receipts: 1 });
      await fixture.restartConfiguration(signing.evidence);
      expect((await fixture.read(`operations/${verified.operationId}`)).body).toEqual(verified);
      const projection = await fixture.read(`notification-endpoints/${verified.resourceRef}`);
      expect(projection).toMatchObject({
        status: 200,
        body: { state: 'ACTIVE', revision: '2', notificationEndpointId: verified.resourceRef },
      });
      expect(Object.keys(projection.body).sort()).toEqual(
        [
          'notificationEndpointId',
          'participantId',
          'channel',
          'destinationRef',
          'state',
          'arbitraryEgress',
          'revision',
          'createdAt',
          'updatedAt',
        ].sort(),
      );
      await assertNotificationRoutingInstallationCases(
        admin,
        runtimeUrl,
        participantId,
        privacyDomainId,
        positive.endpointId,
      );
      const original = await stateOwner().readOriginal(await positive.refresh());
      expect(original).toEqual({
        attemptId: prepared.attemptId,
        state: 'ATTACHED',
        operationId: verified.operationId,
        challengeBytes: proved.challenge_bytes,
        responseBytes: proved.response_bytes,
      });
      expect(await repository().verify(positive.context(), positive.body)).toEqual(verified);
      await positive.restartGateway();
      expect(positive.gateway().verificationStats()).toEqual({ calls: 0, receipts: 1 });
      expect(
        await positive.lease((lease) =>
          stateOwner().dispatch(positive.context(), prepared.attemptId, lease, window()),
        ),
      ).toBe('ATTACHED');
      expect(positive.gateway().verificationStats()).toEqual({ calls: 0, receipts: 1 });
    });

    // Isolated real intents prevent a previous mutation/denial becoming the
    // prerequisite for another case. A fresh key never retries an UNKNOWN effect.
    for (const kind of ['lost-ack', 'rejected', 'expired', 'revoked'] as const) {
      await runScenario(kind, kind === 'expired' ? 3000 : 30000, async (test) => {
        const before = await test.effects();
        if (kind === 'lost-ack') test.gateway().setFault('LOST_ACK');
        if (kind === 'rejected') test.gateway().setVerificationOutcome('REJECTED');
        const attempt = await test.owner.prepare(await test.refresh());
        const outcome = await test.lease((lease) =>
          test.owner.dispatch(test.context(), attempt.attemptId, lease, window()),
        );
        test.assertObserver();
        expect(outcome).toBe(
          kind === 'lost-ack' ? 'UNKNOWN' : kind === 'rejected' ? 'REJECTED' : 'PROVED',
        );
        const stored = await test.readAttempt(attempt.attemptId);
        expect(stored.attempts).toBe(1);
        const historical = await test.owner.readOriginal(test.context());
        if (kind === 'lost-ack') expect(stored.response_bytes).toBeNull();
        else expect(test.authenticate(stored).receiptDigest).toBe(stored.receipt_digest);
        expect(await test.effects()).toEqual(before);
        expect(test.gateway().verificationStats()).toEqual({ calls: 1, receipts: 1 });
        if (kind === 'expired') {
          const expires = parseNotificationVerificationRequest(stored.challenge_bytes).expiresAtMs;
          await delay(Math.max(0, expires - Date.now() + 10));
        }
        if (kind === 'revoked')
          await admin.query(
            "update control.installed_notification_channel set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3",
            [participantId, privacyDomainId, test.credential.credentialRef],
          );
        await expect(repository().verify(await test.refresh(), test.body)).rejects.toThrow();
        expect(await test.effects()).toEqual(before);
        expect(await test.readAttempt(attempt.attemptId)).toEqual(stored);
        await fixture.restartConfiguration(signing.evidence);
        expect(await stateOwner().readOriginal(await test.refresh())).toEqual(historical);
        expect(await stateOwner().prepare(test.context())).toEqual({
          attemptId: attempt.attemptId,
          state: outcome,
        });
        if (kind !== 'revoked') {
          await test.restartGateway();
          expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 1 });
          expect(
            await test.lease((lease) =>
              stateOwner().dispatch(test.context(), attempt.attemptId, lease, window()),
            ),
          ).toBe(outcome);
          expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 1 });
        }
        expect(await test.effects()).toEqual(before);
      });
    }
    await runScenario(
      'public authorization concurrency and filtered readback',
      30000,
      async (test) => {
        const before = await test.effects();
        let operation: Record<string, unknown> | undefined;
        await withPublic(test, async (http) => {
          for (const [headers, status, truth] of [
            [{ Cookie: '' }, 401, 'DENIED'],
            [{ 'X-CSRF-Token': 'invalid-csrf-token-with-valid-length' }, 403, 'DENIED'],
            [{ 'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${id()}` }, 403, 'DENIED'],
            [{ 'If-Match': `"sha256:${'0'.repeat(64)}"` }, 412, 'STALE'],
          ] as const) {
            assertPublicProblem(await http.verify(test.body, headers), status, truth);
            await noPublicEffect(test, before);
          }
          for (const body of [
            { ...test.body, credentialRef: test.credential.credentialRef },
            { ...test.body, targetRef: `urn:openpc:resource:${id()}` },
          ]) {
            assertPublicProblem(await http.verify(body), 400, 'FAILED');
            await noPublicEffect(test, before);
          }
          let arrive!: () => void, resume!: () => void;
          const arrived = new Promise<void>((resolve) => {
            arrive = resolve;
          });
          const released = new Promise<void>((resolve) => {
            resume = resolve;
          });
          test.barrier(async () => {
            arrive();
            await bounded(released, 4000, 'Public concurrency barrier timed out');
          });
          const first = Promise.allSettled([http.verify()]);
          try {
            await bounded(arrived, 5000, 'Public dispatch never reached the real gateway');
            assertPublicProblem(await http.verify(), 409, 'UNKNOWN');
            expect(await test.effects()).toEqual(before);
            expect((await onlyAttempt(test)).state).toBe('DISPATCHED');
          } finally {
            resume();
          }
          const outcome = (await first)[0]!;
          if (outcome.status === 'rejected') throw outcome.reason;
          expect(outcome.value.status).toBe(202);
          operation = outcome.value.body;
          await assertPublicAttachment(test, operation, before);
          expect(test.gateway().verificationStats()).toEqual({ calls: 1, receipts: 1 });
          const projection = await http.read();
          expect(projection).toMatchObject({
            status: 200,
            body: { state: 'ACTIVE', revision: '2', notificationEndpointId: test.body.targetRef },
          });
          expect(Object.keys(projection.body).sort()).toEqual(
            [
              'notificationEndpointId',
              'participantId',
              'channel',
              'destinationRef',
              'arbitraryEgress',
              'state',
              'revision',
              'createdAt',
              'updatedAt',
            ].sort(),
          );
        });
        const attached = await onlyAttempt(test);
        const after = await test.effects();
        await test.restartGateway();
        // New real peer and HTTP root instances; original intent/bytes survive.
        await withPublic(test, async (http) => {
          expect(await http.verify()).toEqual({ status: 202, body: operation });
          const altered = {
            ...test.body,
            inputDigest: digest({ original: test.body.inputDigest, altered: true }),
          };
          const denied = await http.verify(altered);
          expect([409, 412]).toContain(denied.status);
          expect(denied.body.operationId).toBeUndefined();
        });
        expect(await onlyAttempt(test)).toEqual(attached);
        expect(await test.effects()).toEqual(after);
        expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 1 });
        await fixture.restartConfiguration(signing.evidence);
        expect((await fixture.read(`operations/${String(operation!.operationId)}`)).body).toEqual(
          operation,
        );
      },
    );

    await runScenario('public rollback and lost HTTP response recovery', 30000, async (test) => {
      const before = await test.effects();
      let attached: Awaited<ReturnType<typeof onlyAttempt>> | undefined;
      await withPublic(test, async (http) => {
        signing.faults.mode = 'UNAVAILABLE';
        try {
          // The existing external test signer throws a generic error. Preserve
          // the shared UNKNOWN mapping and prove rollback through durable state.
          assertPublicProblem(await http.verify(), 409, 'UNKNOWN');
        } finally {
          signing.faults.mode = undefined;
        }
        const proved = await onlyAttempt(test);
        expect(proved.state).toBe('PROVED');
        expect(await test.effects()).toEqual(before);
        const fault = `test_public_verify_rollback_${test.endpointId.replaceAll('-', '')}`;
        await admin.query(`create function openpc.${fault}() returns trigger language plpgsql as $$ begin
          if NEW.aggregate_type='notification-endpoint' and NEW.participant_id='${participantId}'::uuid and NEW.aggregate_id='${test.endpointId}'::uuid
          then raise exception 'TEST_PUBLIC_NOTIFICATION_OUTBOX'; end if; return NEW; end $$;
          create trigger ${fault} before insert on control.outbox_event for each row execute function openpc.${fault}()`);
        try {
          assertPublicProblem(await http.verify(), 409, 'UNKNOWN');
        } finally {
          await admin.query(
            `drop trigger ${fault} on control.outbox_event; drop function openpc.${fault}()`,
          );
        }
        expect(await onlyAttempt(test)).toEqual(proved);
        expect(await test.effects()).toEqual(before);
        expect(test.gateway().verificationStats()).toEqual({ calls: 1, receipts: 1 });
        http.discardNextResponse();
        await expect(http.verify()).rejects.toThrow();
        attached = await onlyAttempt(test);
        expect(attached).toMatchObject({ state: 'ATTACHED', attempts: 1 });
        expect(attached.challenge_bytes).toEqual(proved.challenge_bytes);
        expect(attached.response_bytes).toEqual(proved.response_bytes);
        expect(attached.receipt_digest).toBe(proved.receipt_digest);
      });
      const after = await test.effects();
      await test.restartGateway();
      await withPublic(test, async (http) => {
        const replay = await http.verify();
        expect(replay.status).toBe(202);
        expect(replay.body.operationId).toBe(attached!.attached_operation_id);
        await assertPublicAttachment(test, replay.body, before);
        expect(await http.verify()).toEqual(replay);
      });
      expect(await onlyAttempt(test)).toEqual(attached);
      expect(await test.effects()).toEqual(after);
      expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 1 });
    });

    for (const kind of ['lost-ack', 'rejected', 'expired', 'revoked'] as const) {
      await runScenario(
        `public ${kind} no-resend`,
        kind === 'expired' ? 3000 : 30000,
        async (test) => {
          const before = await test.effects();
          let retained: Awaited<ReturnType<typeof onlyAttempt>> | undefined;
          if (kind === 'lost-ack') test.gateway().setFault('LOST_ACK');
          if (kind === 'rejected') test.gateway().setVerificationOutcome('REJECTED');
          await withPublic(test, async (http) => {
            if (kind === 'expired' || kind === 'revoked') signing.faults.mode = 'UNAVAILABLE';
            try {
              const first = await http.verify();
              assertPublicProblem(
                first,
                kind === 'rejected' ? 412 : 409,
                kind === 'rejected' ? 'STALE' : 'UNKNOWN',
              );
            } finally {
              signing.faults.mode = undefined;
            }
            retained = await onlyAttempt(test);
            expect(retained.state).toBe(
              kind === 'lost-ack' ? 'UNKNOWN' : kind === 'rejected' ? 'REJECTED' : 'PROVED',
            );
            expect(retained.attached_operation_id).toBeNull();
            test.assertObserver();
            if (kind === 'lost-ack') expect(retained.response_bytes).toBeNull();
            else expect(test.authenticate(retained).receiptDigest).toBe(retained.receipt_digest);
            expect(await test.effects()).toEqual(before);
            if (kind === 'expired') {
              const expires = parseNotificationVerificationRequest(
                retained.challenge_bytes,
              ).expiresAtMs;
              await delay(Math.max(0, expires - Date.now() + 10));
            }
            if (kind === 'revoked')
              await admin.query(
                "update control.installed_notification_channel set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3",
                [participantId, privacyDomainId, test.credential.credentialRef],
              );
            // Expiry is rejected by the final cryptographic owner; its existing
            // generic-error mapping is UNKNOWN, not a claimed no-effect operation.
            assertPublicProblem(
              await http.verify(),
              kind === 'lost-ack' || kind === 'expired' ? 409 : 412,
              kind === 'lost-ack' || kind === 'expired' ? 'UNKNOWN' : 'STALE',
            );
          });
          expect(await onlyAttempt(test)).toEqual(retained);
          expect(await test.effects()).toEqual(before);
          expect(test.gateway().verificationStats()).toEqual({ calls: 1, receipts: 1 });
          await test.restartGateway();
          await withPublic(test, async (http) => {
            assertPublicProblem(
              await http.verify(),
              kind === 'lost-ack' || kind === 'expired' ? 409 : 412,
              kind === 'lost-ack' || kind === 'expired' ? 'UNKNOWN' : 'STALE',
            );
          });
          expect(await onlyAttempt(test)).toEqual(retained);
          expect(await test.effects()).toEqual(before);
          expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 1 });
        },
      );
    }

    await runScenario('public physical credential currentness', 30000, async (test) => {
      const before = await test.effects();
      test.provider.revoke();
      await withPublic(test, async (http) => {
        assertPublicProblem(await http.verify(), 503, 'UNAVAILABLE');
      });
      const retained = await onlyAttempt(test);
      expect(retained).toMatchObject({
        state: 'PREPARED',
        response_bytes: null,
        attached_operation_id: null,
      });
      await withPublic(test, async (http) => {
        assertPublicProblem(await http.verify(), 503, 'UNAVAILABLE');
      });
      expect(await onlyAttempt(test)).toEqual(retained);
      expect(await test.effects()).toEqual(before);
      expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 0 });
    });

    await runScenario('public physical revocation during dispatch', 30000, async (test) => {
      const before = await test.effects();
      let arrive!: () => void, resume!: () => void;
      const arrived = new Promise<void>((resolve) => {
        arrive = resolve;
      });
      const released = new Promise<void>((resolve) => {
        resume = resolve;
      });
      test.barrier(async () => {
        arrive();
        await bounded(released, 4000, 'Physical revocation barrier timed out');
      });
      await withPublic(test, async (http) => {
        const result = Promise.allSettled([http.verify()]);
        try {
          await bounded(arrived, 5000, 'No live verification to revoke');
          const dispatched = await onlyAttempt(test);
          expect(dispatched.state).toBe('DISPATCHED');
          expect(
            parseNotificationVerificationRequest(dispatched.challenge_bytes).expiresAtMs,
          ).toBeGreaterThan(Date.now());
          test.provider.revoke();
        } finally {
          resume();
        }
        const outcome = (await result)[0]!;
        if (outcome.status === 'rejected') throw outcome.reason;
        assertPublicProblem(outcome.value, 409, 'UNKNOWN');
        test.assertObserver();
        const retained = await onlyAttempt(test);
        expect(retained).toMatchObject({
          state: 'UNKNOWN',
          response_bytes: null,
          attached_operation_id: null,
        });
        assertPublicProblem(await http.verify(), 409, 'UNKNOWN');
        expect(await onlyAttempt(test)).toEqual(retained);
      });
      expect(await test.effects()).toEqual(before);
      expect(test.gateway().verificationStats().calls).toBe(1);
    });
    await runScenario(
      'runtime concrete transport public verify and closed-provider restart readback',
      30000,
      async (test) => {
        const before = await test.effects();
        let original: Record<string, unknown> | undefined;
        await withRuntime(test, async (http) => {
          const result = await http.verify();
          expect(result.status).toBe(202);
          original = result.body;
          await assertPublicAttachment(test, result.body, before);
          expect((await http.read()).body).toMatchObject({ state: 'ACTIVE', revision: '2' });
        });
        const attached = await onlyAttempt(test),
          effects = await test.effects(),
          stats = test.gateway().verificationStats();
        test.provider.close();
        await withRuntime(
          test,
          async (http) => {
            const replay = await http.verify();
            expect(replay.status).toBe(202);
            expect(replay.body).toEqual(original);
            expect((await http.read()).body).toMatchObject({ state: 'ACTIVE', revision: '2' });
          },
          false,
        );
        expect(await onlyAttempt(test)).toEqual(attached);
        expect(await test.effects()).toEqual(effects);
        expect(test.gateway().verificationStats()).toEqual(stats);
      },
    );
    await runScenario(
      'runtime missing peer preserves metadata and closes only verification',
      30000,
      async (test) => {
        const before = await test.effects();
        await withRuntime(
          test,
          async (http) => {
            expect((await http.read()).body).toMatchObject({ state: 'DISABLED', revision: '1' });
            assertPublicProblem(await http.verify(), 503, 'UNAVAILABLE');
          },
          false,
        );
        expect(await test.effects()).toEqual(before);
        expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 0 });
        expect(await onlyAttempt(test)).toMatchObject({ state: 'PREPARED', response_bytes: null });
      },
    );
    await runScenario(
      'runtime does not restore a terminal physical provider',
      30000,
      async (test) => {
        test.provider.revoke();
        const before = await test.effects();
        await withRuntime(test, async (http) => {
          assertPublicProblem(await http.verify(), 503, 'UNAVAILABLE');
        });
        expect(await test.effects()).toEqual(before);
        expect(test.gateway().verificationStats()).toEqual({ calls: 0, receipts: 0 });
      },
    );
    await runScenario(
      'runtime actual peer disconnect preserves UNKNOWN original without resend',
      30000,
      async (test) => {
        const before = await test.effects();
        let arrived!: () => void, release!: () => void;
        const entry = new Promise<void>((resolve) => {
          arrived = resolve;
        });
        const released = new Promise<void>((resolve) => {
          release = resolve;
        });
        test.barrier(async () => {
          arrived();
          await bounded(released, 4000, 'Runtime disconnect barrier');
        });
        await withRuntime(test, async (http, disconnect) => {
          const result = http.verify();
          void result.catch(() => {});
          try {
            await bounded(entry, 5000, 'No live original dispatch');
            expect((await onlyAttempt(test)).state).toBe('DISPATCHED');
            disconnect();
          } finally {
            release();
          }
          assertPublicProblem(await result, 409, 'UNKNOWN');
          const original = await onlyAttempt(test);
          expect(['DISPATCHED', 'UNKNOWN']).toContain(original.state);
          assertPublicProblem(await http.verify(), 409, 'UNKNOWN');
          const retained = await onlyAttempt(test);
          expect(retained.attempt_id).toBe(original.attempt_id);
          expect(retained.challenge_bytes).toEqual(original.challenge_bytes);
        });
        expect(await test.effects()).toEqual(before);
        expect(test.gateway().verificationStats().calls).toBe(1);
      },
    );
  } catch (error) {
    failures.push(error);
  } finally {
    signing.faults.mode = undefined;
    for (const gateway of gateways) await cleanup(() => gateway.close());
    for (const provider of providers) await cleanup(() => provider.close());
    await cleanup(() => recipient.close());
    await cleanup(() => recipientPool.end());
    await cleanup(() => verificationPool.end());
    credentialBytes?.fill(0);
    for (const material of keys) material.fill(0);
    outbound?.privateKey.fill(0);
    outbound?.server.privateKey.fill(0);
    await cleanup(() => outbound?.close());
    // Keep the original external journals on any failure for causal diagnosis.
    if (!failures.length && root) await cleanup(() => rm(root!, { recursive: true, force: true }));
  }
  if (failures.length)
    throw new AggregateError(failures, 'Joined notification verification failed');
}
