import Fastify, { type FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import { createPrivateKey, generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { createServer } from 'node:net';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { TLSSocket } from 'node:tls';
import { expect } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { notificationCredentialEncoding } from '../../../services/identity-service/src/domain/notification-credential-material.js';
import type { NotificationCredentialProvider } from '../../../services/identity-service/src/domain/notification-credential-material.js';
import { createLocalConfigurationAuthorizer } from '../../../services/control-api/src/configuration/local-authorizer.js';
import { registerConfigurationRoutes } from '../../../services/control-api/src/configuration/http.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { EvidenceExportWorker } from '../../../services/control-api/src/evidence/export-worker.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import type { EvidenceScope } from '../../../services/control-api/src/evidence/segment.js';
import type { EvidenceKmsInstallationInput } from '../../../services/control-api/src/evidence/kms-contracts.js';
import { notificationPayloadEncryptionProfileDigest } from '../../../services/control-api/src/evidence/notification-payload-crypto.js';
import { createNotificationVerificationRuntime } from '../../../services/control-api/src/notifications/endpoint-verification-runtime.js';
import { installInitialNotificationRouting } from '../../../services/control-api/src/notifications/routing-installation.js';
import type { NotificationRoutingInstallation } from '../../../services/control-api/src/notifications/routing-installation-contract.js';
import type { NotificationChannelInstallation } from '../../../services/control-api/src/notifications/endpoint-admission.js';
import {
  evidenceKeyId,
  signNotificationClaim,
} from '../../../packages/security-kernel/src/index.js';
import {
  encodeCbor,
  type CborValue,
} from '../../../packages/security-kernel/src/canonical-cbor.js';
import { createTestNotificationCredentialProvider } from '../../../scripts/operations/test-notification-credential-provider.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import type { contractAdministrationFixture } from './contract-administration-fixture.js';
import {
  NotificationKeyCustody,
  notificationKeyFailure,
} from '../../../services/control-api/src/evidence/notification-key-custody.js';
import {
  notificationKeyFile,
  validateNotificationKeyPreparation,
  type NotificationKeyPrepareInput,
  type NotificationKeyPreparation,
} from '../../../services/control-api/src/evidence/notification-key-contracts.js';
import {
  openVaultDirectory,
  putVaultFile,
  readVaultFile,
} from '../../../services/control-api/src/evidence/immutable-vault.js';

const methods = [
  'prepare',
  'seal',
  'reconcile',
  'readOriginal',
  'verifyRetained',
  'protection',
] as const;
type Method = (typeof methods)[number] | 'seal-lost-response';
type Call = (
  method: Method,
  input: unknown,
  foreign?: boolean,
) => Promise<{ status: number; body: unknown }>;
const selector = (p: NotificationKeyPreparation) => ({
  participantId: p.input.scope.participantId,
  privacyDomainId: p.input.scope.privacyDomainId,
  producerTrustDigest: p.input.producerTrustDigest,
  kmsInstallationDigest: p.input.kmsInstallationDigest,
  preparationId: p.preparationId,
});

/** Mount only in the existing real-mTLS PG fixture. No alternative listener,
 * database, Identity kernel, admission DTO or in-memory custody implementation.
 * The caller's HTTPS client must retain certificate verification and real peers. */
export function installNotificationKeyCustodyCaseRoutes(
  app: FastifyInstance,
  custody: NotificationKeyCustody,
) {
  for (const method of [...methods, 'seal-lost-response'] as const)
    app.post(`/test/notification-key/${method}`, async (request, reply) => {
      try {
        const socket = request.raw.socket as TLSSocket,
          signal = new AbortController().signal;
        const result =
          method === 'prepare'
            ? await custody.prepare(socket, request.body)
            : method === 'readOriginal'
              ? await custody.readOriginal(socket, request.body)
              : method === 'protection'
                ? await custody.protection(socket, request.body)
                : method === 'reconcile'
                  ? await custody.reconcile(socket, request.body, signal)
                  : method === 'verifyRetained'
                    ? await custody.verifyRetained(socket, request.body, signal)
                    : await custody.seal(socket, request.body, signal);
        if (method === 'seal-lost-response') {
          reply.hijack();
          reply.raw.destroy();
          return;
        }
        return result;
      } catch (error) {
        return reply.code(403).send({ code: notificationKeyFailure(error).code });
      }
    });
}

/** Existing genuine governed-export/current-route fixture supplies FIVE isolated
 * completed exports and their prepared completion records, all under one real
 * installation. This helper never seeds those business states. Each call uses
 * the existing real TLS route above. Admin is only observation and scoped fault
 * injection; all successful custody mutations traverse Identity/runtime owners. */
export async function assertNotificationKeyCustodyCases(input: {
  admin: Pool;
  call: Call;
  vaultDirectory: string;
  cases: {
    positive: NotificationKeyPrepareInput;
    rollback: NotificationKeyPrepareInput;
    lostAck: NotificationKeyPrepareInput;
    failedPersist: NotificationKeyPrepareInput;
    unknown: NotificationKeyPrepareInput;
  };
  provider: {
    counters(): { prepareEffects: number; unwrapCalls: number };
    loseNextResponse(operation: 'UNWRAP'): void;
  };
}) {
  const { admin, call, cases, provider } = input,
    scope = cases.positive.scope;
  expect(new Set(Object.values(cases).map((c) => c.evidenceExportId)).size).toBe(5);
  for (const c of Object.values(cases)) {
    expect(c.scope).toEqual(scope);
    expect(c.kmsInstallationDigest).toBe(cases.positive.kmsInstallationDigest);
    expect(c.routing).toEqual(cases.positive.routing);
  }
  const untouched = async () => {
    const result: Record<string, unknown> = {};
    // Consumer declarations are not installation or delivery authority. Preserve
    // ABSENT as a distinct observation; do not manufacture future owner tables.
    for (const table of [
      'notification',
      'notification_occurrence',
      'notification_delivery',
      'notification_payload_object',
      'notification_source_inbox',
      'notification_source_cursor',
    ]) {
      const installed = await admin.query<{ installed: boolean }>(
        'select to_regclass($1) is not null installed',
        [`control.${table}`],
      );
      result[table] = installed.rows[0]?.installed
        ? (
            await admin.query(
              table === 'notification_source_cursor'
                ? `select coalesce(jsonb_agg(to_jsonb(c) order by to_jsonb(c)::text),'[]'::jsonb) value
                   from control.${table} c where participant_id=$1 and privacy_domain_id=$2`
                : `select count(*)::int value from control.${table} where participant_id=$1 and privacy_domain_id=$2`,
              [scope.participantId, scope.privacyDomainId],
            )
          ).rows[0].value
        : 'ABSENT';
    }
    result.notification_events = (
      await admin.query(
        `select count(*)::int value from control.outbox_event where participant_id=$1 and privacy_domain_id=$2
         and (event_type ilike '%notification%' or aggregate_type like 'notification%')`,
        [scope.participantId, scope.privacyDomainId],
      )
    ).rows[0].value;
    return result;
  };
  const baseline = await untouched();
  const prepare = async (value: NotificationKeyPrepareInput) => {
    const result = await call('prepare', value);
    expect(result.status).toBe(200);
    return validateNotificationKeyPreparation(result.body);
  };
  const count = async (p: NotificationKeyPreparation) =>
    (
      await admin.query(
        `select count(*)::int count from control.evidence_kms_exchange
    where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and kind='UNWRAP'
    and convert_from(request_bytes,'UTF8')::jsonb->>'keyUse'='ENCRYPT'`,
        [scope.participantId, scope.privacyDomainId, p.preparationId],
      )
    ).rows[0].count;
  const directory = await openVaultDirectory(input.vaultDirectory);
  const concurrent = await Promise.all([prepare(cases.positive), prepare(cases.positive)]);
  expect(concurrent[0]).toEqual(concurrent[1]);
  const positive = concurrent[0]!,
    q = selector(positive);
  expect(await call('readOriginal', q, true)).toMatchObject({ status: 403 });
  for (const extra of [
    { ready: true },
    { purpose: 'OTHER' },
    { keyId: 'latest' },
    { payloadDigest: 'private' },
  ])
    expect(await call('prepare', { ...cases.positive, ...extra })).toMatchObject({ status: 403 });
  const beforeProtection = provider.counters();
  const pendingProtection = await call('protection', q);
  expect(pendingProtection).toMatchObject({
    status: 200,
    body: {
      retirementAllowed: false,
      blockers: expect.arrayContaining(['CONSUMER_CLOSURE_UNAVAILABLE', 'CUSTODY_UNRESOLVED']),
    },
  });
  expect(Object.keys(pendingProtection.body as object).sort()).toEqual([
    'blockers',
    'retirementAllowed',
  ]);
  expect(provider.counters()).toEqual(beforeProtection);
  const racingSeals = await Promise.all([call('seal', q), call('seal', q)]);
  for (const result of racingSeals) expect([200, 403]).toContain(result.status);
  // Competing callers may lose admission or receipt ordering. Re-enter the same
  // original preparation: recovery must settle it with one encryption effect.
  const sealed = await call('seal', q);
  expect(sealed).toMatchObject({
    status: 200,
    body: { state: 'CUSTODIED', publicationAuthority: 'NONE' },
  });
  const original = await readVaultFile(directory, notificationKeyFile(positive), 131072);
  const counters = provider.counters();
  expect(await call('seal', q)).toMatchObject({ status: 200, body: sealed.body });
  expect(await readVaultFile(directory, notificationKeyFile(positive), 131072)).toEqual(original);
  expect(await count(positive)).toBe(1);
  expect(provider.counters().prepareEffects).toBe(counters.prepareEffects);
  const protectedEffects = async () => {
    const snapshot: Record<string, string[]> = {};
    for (const [table, column] of [
      ['notification_key_preparation', 'preparation_id'],
      ['notification_key_ciphertext', 'preparation_id'],
      ['evidence_kms_attempt', 'attempt_id'],
      ['evidence_wrapped_key', 'attempt_id'],
      ['evidence_kms_exchange', 'attempt_id'],
    ]) {
      const result = await admin.query<{ original: string }>(
        `select to_jsonb(t)::text original from control.${table} t where participant_id=$1 and privacy_domain_id=$2 and ${column}=$3 order by to_jsonb(t)::text`,
        [scope.participantId, scope.privacyDomainId, q.preparationId],
      );
      snapshot[table!] = result.rows.map((row) => row.original);
    }
    return snapshot;
  };
  const effectsBeforeProtection = await protectedEffects(),
    countersBeforeProtection = provider.counters();
  const protection = await call('protection', q);
  expect(protection).toMatchObject({
    status: 200,
    body: {
      retirementAllowed: false,
      blockers: expect.arrayContaining(['CONSUMER_CLOSURE_UNAVAILABLE']),
    },
  });

  expect(Object.keys(protection.body as object).sort()).toEqual(['blockers', 'retirementAllowed']);
  expect(await call('protection', q, true)).toMatchObject({ status: 403 });
  expect(await call('protection', { ...q, privacyDomainId: id() })).toMatchObject({ status: 403 });
  expect(await protectedEffects()).toEqual(effectsBeforeProtection);
  expect(provider.counters()).toEqual(countersBeforeProtection);
  expect(await readVaultFile(directory, notificationKeyFile(positive), 131072)).toEqual(original);
  expect(await untouched()).toEqual(baseline);

  const rollback = await prepare(cases.rollback),
    name = `notification_key_fault_${rollback.preparationId.replaceAll('-', '')}`;
  const fault = await admin.connect();
  try {
    // A real deferred SQL failure AFTER immutable persistence, not a fake store.
    await fault.query(
      `create function pg_temp.${name}() returns trigger language plpgsql as $$ begin raise exception 'TEST_NOTIFICATION_POST_PERSIST_ROLLBACK'; end $$`,
    );
    await fault.query(`create constraint trigger ${name} after insert on control.notification_key_ciphertext deferrable initially deferred
      for each row when(new.preparation_id='${rollback.preparationId}'::uuid) execute function pg_temp.${name}()`);
    expect(await call('seal', selector(rollback))).toMatchObject({ status: 403 });
    expect(
      (
        await admin.query(
          'select 1 from control.notification_key_ciphertext where preparation_id=$1',
          [rollback.preparationId],
        )
      ).rowCount,
    ).toBe(0);
  } finally {
    try {
      await fault.query(`drop trigger if exists ${name} on control.notification_key_ciphertext`);
    } finally {
      try {
        await fault.query(`drop function if exists pg_temp.${name}()`);
      } finally {
        fault.release();
      }
    }
  }
  const orphan = await readVaultFile(directory, notificationKeyFile(rollback), 131072);
  expect(await call('readOriginal', selector(rollback))).toMatchObject({
    status: 200,
    body: { state: 'UNKNOWN' },
  });
  expect(await call('reconcile', selector(rollback))).toMatchObject({
    status: 200,
    body: { state: 'CUSTODIED' },
  });
  expect(await readVaultFile(directory, notificationKeyFile(rollback), 131072)).toEqual(orphan);
  expect(await count(rollback)).toBe(1);

  const lostAck = await prepare(cases.lostAck);
  await expect(call('seal-lost-response', selector(lostAck))).rejects.toThrow();
  const ackOriginal = await readVaultFile(directory, notificationKeyFile(lostAck), 131072);
  expect(await call('readOriginal', selector(lostAck))).toMatchObject({
    status: 200,
    body: { state: 'CUSTODIED' },
  });
  expect(await call('reconcile', selector(lostAck))).toMatchObject({
    status: 200,
    body: { state: 'CUSTODIED' },
  });
  expect(await readVaultFile(directory, notificationKeyFile(lostAck), 131072)).toEqual(ackOriginal);
  expect(await count(lostAck)).toBe(1);

  const failed = await prepare(cases.failedPersist);
  // Immutable storage conflict must never be overwritten or converted to success.
  const corruption = Buffer.from('owned storage fault');
  await putVaultFile(directory, notificationKeyFile(failed), corruption);
  expect(await call('seal', selector(failed))).toMatchObject({ status: 403 });
  expect(await call('reconcile', selector(failed))).toMatchObject({ status: 403 });
  expect(await readVaultFile(directory, notificationKeyFile(failed), 131072)).toEqual(corruption);
  expect(await count(failed)).toBe(1);

  const unknown = await prepare(cases.unknown);
  provider.loseNextResponse('UNWRAP');
  expect(await call('seal', selector(unknown))).toMatchObject({ status: 403 });
  expect(await call('readOriginal', selector(unknown))).toMatchObject({
    status: 200,
    body: { state: 'UNKNOWN' },
  });
  const uncertainCount = provider.counters().unwrapCalls;
  expect(await call('seal', selector(unknown))).toMatchObject({
    status: 403,
    body: { code: 'UNKNOWN' },
  });
  expect(provider.counters().unwrapCalls).toBe(uncertainCount);
  expect(await count(unknown)).toBe(1);
  await expect(readVaultFile(directory, notificationKeyFile(unknown), 131072)).rejects.toThrow();
  expect(
    (
      await admin.query(
        `select 1 from control.notification_key_ciphertext
         where participant_id=$1 and privacy_domain_id=$2 and preparation_id=$3`,
        [scope.participantId, scope.privacyDomainId, unknown.preparationId],
      )
    ).rowCount,
  ).toBe(0);
  expect(await untouched()).toEqual(baseline);
  return { positive, original, rollback, orphan, lostAck, ackOriginal, unknown };
}

/** Invoke at the parent's ACTUAL rotation/revocation and populated restore
 * checkpoints, after its real provider controls/restore owner have completed.
 * A boolean here selects the expected denial; it is never service authority. */
export async function assertNotificationKeyRetainedReadback(input: {
  call: Call;
  vaultDirectory: string;
  preparation: NotificationKeyPreparation;
  original: Buffer;
  expected: 'RETAINED_ALLOWED' | 'REVOKED_OR_RESTORED_DENIED';
}) {
  const q = selector(input.preparation);
  const response = await input.call('verifyRetained', q);
  expect(response.status).toBe(input.expected === 'RETAINED_ALLOWED' ? 200 : 403);
  expect(await input.call('readOriginal', q)).toMatchObject({
    status: 200,
    body: { state: 'CUSTODIED', publicationAuthority: 'NONE' },
  });
  expect(
    await readVaultFile(
      await openVaultDirectory(input.vaultDirectory),
      notificationKeyFile(input.preparation),
      131072,
    ),
  ).toEqual(input.original);
}

/** Build source state through the ordinary HTTP approval/step-up path and real
 * authentication custody/export owners. No completion/output/approval rows are
 * seeded. Five different prefix selections isolate the five business intents. */
export async function prepareNotificationKeyExports(input: {
  fixture: Awaited<ReturnType<typeof contractAdministrationFixture>>;
  worker: Pool;
  scope: EvidenceScope;
  root: string;
  prepareCompletion(evidenceExportId: string): Promise<{ status: number; body: unknown }>;
}) {
  const { fixture, worker, scope } = input;
  for (let index = 0; index < 5; index++)
    await fixture.selectPrivacyContext('maker', { freshStepUp: true });
  const custody = new EvidenceCustody(worker),
    key = randomBytes(32),
    keyId = 'custody-source-key';
  try {
    expect(
      await custody.ingestAuthentication(
        scope,
        { keyId, key },
        new Date(Date.now() + 86400000).toISOString().replace('Z', '000Z'),
        262144,
      ),
    ).not.toBeNull();
    const vault = await LocalEvidenceVault.open(
      join(input.root, 'notification-source-vault'),
      'notification-source-sink',
    );
    expect(await custody.exportNext(scope, vault)).not.toBeNull();
    const exporter = new EvidenceExportWorker(worker, vault, async (actual, requested) => {
      expect(actual).toEqual(scope);
      expect(requested).toBe(keyId);
      return key;
    });
    const exports: string[] = [];
    for (let count = 1; count <= 5; count++) {
      const created = await fixture.attemptMutation(
        'evidence-exports/from-selection',
        'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          selection: {
            streamId: scope.streamId,
            fromSequence: '1',
            throughSequence: String(count),
            redactionProfileId: 'pc.evidence.minimized-audit.v1',
          },
        },
      );
      expect(created).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
      const ref = String(created.body.resourceRef),
        evidenceExportId = ref.slice(-36);
      const requested = await fixture.read(`evidence-exports/${ref}`);
      expect(requested).toMatchObject({ status: 200, body: { state: 'REQUESTED' } });
      const start = await fixture.prepareMutation(
        `evidence-exports/${ref}/export`,
        'ACT-EVIDENCE_EXPORT_RECORDS-V1',
        {
          targetRef: ref,
          expectedRevision: '1',
          inputDigest: String(requested.body.requestDigest),
        },
        true,
      );
      await start.stepUp();
      expect(await start.commit()).toMatchObject({ status: 202, body: { state: 'ACCEPTED' } });
      expect(await exporter.runNext(scope)).toMatchObject({ evidenceExportId, state: 'SUCCEEDED' });
      expect(await fixture.read(`evidence-exports/${ref}`)).toMatchObject({
        status: 200,
        body: { state: 'SUCCEEDED' },
      });
      expect(await input.prepareCompletion(evidenceExportId)).toMatchObject({
        status: 200,
        body: { state: 'PREPARED' },
      });
      exports.push(evidenceExportId);
    }
    expect(new Set(exports).size).toBe(5);
    return exports;
  } finally {
    key.fill(0);
  }
}

/** Reuse the existing physical provider/gateway and production runtime roots.
 * Initial signed profiles are fixtures; endpoint CREATE/VERIFY are real public
 * commands. This composition owns only its bounded listeners/pools and closes
 * them before the parent's existing populated-store recovery. */
export async function prepareNotificationKeyRouting(input: {
  admin: Pool;
  installer: Pool;
  runtimeUrl: string;
  fixture: Awaited<ReturnType<typeof contractAdministrationFixture>>;
  peer: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>;
  principalId: string;
  credentialId: string;
  workloadId: string;
  pins: EvidenceKmsInstallationInput;
  root: string;
}) {
  const { fixture, pins, peer } = input;
  const scope = { participantId: pins.participantId, privacyDomainId: pins.privacyDomainId };
  const cleanup: (() => unknown | Promise<unknown>)[] = [];
  const close = async () => {
    const errors: unknown[] = [];
    for (const stop of cleanup.splice(0).reverse()) {
      try {
        await stop();
      } catch (error) {
        errors.push(error);
      }
    }
    if (errors.length)
      throw new AggregateError(errors, 'Notification custody setup cleanup failed');
  };
  try {
    const signing = await evidenceGovernanceSigningFixture(
      input.admin,
      scope.participantId,
      scope.privacyDomainId,
      'notification-endpoint',
    );
    cleanup.push(() => signing.close());
    await fixture.restartConfiguration(signing.evidence);
    const outbound = await runtimeSnapshotTlsFixture(
      'urn:openpc:test:notification-custody-gateway',
    );
    cleanup.push(() => outbound.close());
    const key = () => {
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
      cleanup.push(() => privateKey.fill(0));
      return { privateKey, spki: pair.publicKey.export({ type: 'spki', format: 'der' }) };
    };
    const issuer = key(),
      gatewaySigner = key(),
      verificationSigner = key();
    const privateDer = createPrivateKey(outbound.privateKey).export({
      format: 'der',
      type: 'pkcs8',
    });
    let material: Buffer;
    try {
      material = encodeCbor(
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
    cleanup.push(() => material.fill(0));
    const reservation = createServer();
    let port: number;
    try {
      await new Promise<void>((resolve, reject) => {
        reservation.once('error', reject);
        reservation.listen(0, '127.0.0.1', resolve);
      });
      const address = reservation.address();
      if (!address || typeof address === 'string') throw new Error('Gateway port unavailable');
      port = address.port;
    } finally {
      if (reservation.listening)
        await new Promise<void>((resolve, reject) =>
          reservation.close((error) => (error ? reject(error) : resolve())),
        );
    }
    const now = Date.now(),
      destinationRef = `urn:openpc:resource:${id()}`,
      credentialRef = `urn:openpc:resource:${id()}`;
    const credential: NotificationChannelInstallation['credential'] = {
      ...scope,
      credentialRef,
      channel: 'WEBHOOK',
      destinationRef,
      secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
      owner: 'LS-NOTIFICATION',
      reference: `secret://local/notification-custody-${id()}#1`,
      version: '1',
      epoch: '1',
      fingerprint: sha256(material),
      state: 'ACTIVE',
      validFromMs: now - 1000,
      validUntilMs: now + 3600000,
    };
    const transport = {
      protocol: 'OPENPC_NOTIFICATION_GATEWAY_V1' as const,
      channel: 'WEBHOOK' as const,
      destinationRef,
      credentialRef,
      endpoint: `https://127.0.0.1:${port}/`,
      addresses: ['127.0.0.1'],
      serverSpkiDigest: sha256(
        new X509Certificate(outbound.server.certificate).publicKey.export({
          type: 'spki',
          format: 'der',
        }),
      ),
      requestTimeoutMs: 10000,
      maxPayloadBytes: 65536,
    };
    const channel = signNotificationClaim(
      'NotificationChannelProfileV1',
      issuer.privateKey,
      issuer.spki,
      {
        ...scope,
        environmentId: pins.environmentId,
        profileId: id(),
        revision: '1',
        validFromMs: now - 1000,
        validUntilMs: now + 3600000,
        transportProfileDigest: sha256(transport),
        receiptSignerSpki: gatewaySigner.spki.toString('hex'),
        issuerKeyId: evidenceKeyId(issuer.spki),
      },
    );
    const trust = {
      ...scope,
      environmentId: pins.environmentId,
      signedProfileDigest: sha256(channel.cose),
      issuerSpkiHex: issuer.spki.toString('hex'),
    };
    const verification = signNotificationClaim(
      'NotificationVerificationProfileV1',
      issuer.privateKey,
      issuer.spki,
      {
        ...scope,
        environmentId: pins.environmentId,
        profileId: id(),
        revision: '1',
        validFromMs: now - 1000,
        validUntilMs: now + 3600000,
        signedChannelProfileDigest: trust.signedProfileDigest,
        credentialBindingDigest: sha256(credential),
        verificationSignerSpki: verificationSigner.spki.toString('hex'),
        issuerKeyId: evidenceKeyId(issuer.spki),
      },
    );
    const installation: NotificationChannelInstallation = {
      credential,
      channelTrust: trust,
      channelSigned: {
        transport,
        payloadHex: channel.payload.toString('hex'),
        coseHex: channel.cose.toString('hex'),
      },
      verification: {
        trust: { ...trust, signedProfileDigest: sha256(verification.cose) },
        signed: {
          payloadHex: verification.payload.toString('hex'),
          coseHex: verification.cose.toString('hex'),
        },
      },
      principalId: input.principalId,
      workloadCredentialId: input.credentialId,
      workloadId: `urn:openpc:workload:${input.workloadId}`,
      workloadEpoch: '1',
      admissionReference: 'notification-custody-initial-channel',
    };
    const provider = createTestNotificationCredentialProvider(credential, material);
    cleanup.push(() => provider.close());
    const installationPool = new Pool({
      connectionString: input.admin.options.connectionString,
      max: 1,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
      idle_in_transaction_session_timeout: 30000,
    });
    cleanup.push(() => installationPool.end());
    // Existing JavaScript root has no declaration module. Keep this consumer's
    // structural boundary explicit; the root independently validates all inputs.
    const bootstrapModule = '../local-runtime/notification-runtime-bootstrap.mjs';
    const {
      prepareNotificationRuntimeFixtures,
      notificationRuntimeDeliveryStats,
      withNotificationRuntimeDeliveryOutcome,
    } = (await import(bootstrapModule)) as {
      notificationRuntimeDeliveryStats(
        fixture: unknown,
        scope: { participantId: string; privacyDomainId: string; destinationRef: string },
      ): { calls: number; readbacks: number; delivered: number; receipts: number; sockets: number };
      withNotificationRuntimeDeliveryOutcome<T>(
        fixture: unknown,
        scope: { participantId: string; privacyDomainId: string; destinationRef: string },
        outcome: 'DELIVERED' | 'RETRYABLE_NO_EFFECT' | 'PERMANENT_FAILURE' | 'AMBIGUOUS',
        use: () => Promise<T>,
      ): Promise<T>;
      prepareNotificationRuntimeFixtures(input: {
        installationPool: Pool;
        entries: {
          installation: NotificationChannelInstallation;
          provider: NotificationCredentialProvider;
          journalPath: string;
          gatewayTls: { key: Buffer; cert: Buffer; ca: Buffer };
          gatewaySignerPrivateKey: Buffer;
          gatewaySignerSpki: Buffer;
          verificationSignerPrivateKey: Buffer;
          verificationSignerSpki: Buffer;
          clientSpkiDigest: string;
        }[];
      }): Promise<{
        close(): Promise<void>;
        credentialProvider: NotificationCredentialProvider;
        connectWorkload(input: {
          host: string;
          port: number;
          ca: Buffer;
          certificate: Buffer;
          privateKey: Buffer;
        }): Promise<void>;
      }>;
    };
    const fixtures = await prepareNotificationRuntimeFixtures({
      installationPool,
      entries: [
        {
          installation,
          provider,
          journalPath: join(input.root, 'notification-custody-gateway'),
          gatewayTls: {
            key: outbound.server.privateKey,
            cert: outbound.server.certificate,
            ca: outbound.server.ca,
          },
          gatewaySignerPrivateKey: gatewaySigner.privateKey,
          gatewaySignerSpki: gatewaySigner.spki,
          verificationSignerPrivateKey: verificationSigner.privateKey,
          verificationSignerSpki: verificationSigner.spki,
          clientSpkiDigest: sha256(
            outbound.parsed.publicKey.export({ type: 'spki', format: 'der' }),
          ),
        },
      ],
    });
    cleanup.push(() => fixtures.close());
    const verifier = createLocalIdentityRuntimeVerifier([
      await readFile(`${fixture.service.directory}/public.der`),
    ]);
    const runtime = createNotificationVerificationRuntime({
      database: { connectionString: input.runtimeUrl },
      tls: peer.server,
      identityRuntimeVerifier: verifier,
      businessEvidence: signing.evidence,
      credentialProvider: fixtures.credentialProvider,
    });
    cleanup.push(() => runtime.close());
    const listen = await runtime.start({ host: '127.0.0.1', port: 0 });
    await fixtures.connectWorkload({
      ...listen,
      ca: peer.server.ca,
      certificate: peer.certificate,
      privateKey: peer.privateKey,
    });
    await expect
      .poll(
        () =>
          runtime.preflight(credential).then(
            () => true,
            () => false,
          ),
        { timeout: 5000 },
      )
      .toBe(true);
    const pool = new Pool({ connectionString: input.runtimeUrl, max: 2 });
    cleanup.push(() => pool.end());
    const http = Fastify({ logger: false, trustProxy: false });
    cleanup.push(() => http.close());
    registerConfigurationRoutes(http, {
      pool,
      identityRuntimeVerifier: verifier,
      authorizer: createLocalConfigurationAuthorizer(
        fixture.service.identityUrl,
        fixture.service.identityInternalToken,
        scope.privacyDomainId,
      ),
      businessEvidence: signing.evidence,
      notificationEndpointOwners: runtime.owners,
      notificationEndpointVerification: runtime.workflow,
    });
    const address = await http.listen({ host: '127.0.0.1', port: 0 });
    const createAction = 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1';
    const created = fixture.ordinaryMutation('notification-endpoints', createAction, {
      participantId: `urn:openpc:participant:${scope.participantId}`,
      channel: 'WEBHOOK',
      destinationRef,
      arbitraryEgress: false,
      reason: 'Notification ciphertext custody acceptance',
    });
    expect(await created.call()).toMatchObject({ status: 403 });
    // This catalogue operation requires step-up, not maker/checker proposal
    // staging. Match the public Workbench: use a review correlation UUID and
    // bind the real WebAuthn verification to the exact request digest. The API
    // still chooses the endpoint aggregate and consumes the verified assertion.
    await fixture.governance.client.stepUp(
      fixture.governance.maker,
      createAction,
      id(),
      created.hash,
    );
    const result = await created.call();
    expect(result).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
    const ref = String(result.body.resourceRef),
      endpointId = ref.slice(-36),
      action = 'ACT-NOTIFICATION_UPDATE_VERIFY-V1';
    const { client, maker } = fixture.governance;
    const body = {
      actionIntentId: action,
      actionIntentDigest: client.actionDigests.get(action)!,
      targetRef: ref,
      expectedRevision: '1',
      inputDigest: sha256({ targetRef: ref, expectedRevision: '1', transition: 'VERIFY' }),
      reason: 'Notification custody real gateway verification',
    };
    expect(
      await client.request(`${address}/api/v1/notification-endpoints/${ref}/verify`, maker, body, {
        'OpenPC-API-Version': '1',
        'OpenPC-Participant-ID': `urn:openpc:participant:${scope.participantId}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${scope.privacyDomainId}`,
        'X-Request-ID': id(),
        'X-Correlation-ID': id(),
        'Idempotency-Key': id(),
        'OpenPC-Action-Intent-Digest': body.actionIntentDigest,
        'If-Match': `"${sha256({ resourceId: endpointId, revision: '1' })}"`,
        'X-CSRF-Token': await client.csrf(maker, action, address),
      }),
    ).toMatchObject({ status: 202, body: { state: 'SUCCEEDED' } });
    const endpoint = await fixture.read(`notification-endpoints/${ref}`);
    expect(endpoint).toMatchObject({ status: 200, body: { state: 'ACTIVE', revision: '2' } });
    const template: NotificationRoutingInstallation['template'] = {
      schema: 'OPENPC_EVIDENCE_EXPORT_NOTIFICATION_TEMPLATE_V1',
      templateId: id(),
      revision: '1',
      sourceEvent: 'EvidenceExportCompleted',
      format: 'PLAIN_TEXT',
      subject: [{ kind: 'TEXT', value: 'Evidence export complete' }],
      body: [
        { kind: 'FIELD', field: 'evidenceExportId' },
        { kind: 'FIELD', field: 'checkpoint' },
        { kind: 'FIELD', field: 'outputDigest' },
        { kind: 'FIELD', field: 'recordCount' },
      ],
    };
    const recipientSet: NotificationRoutingInstallation['recipientSet'] = {
      schema: 'OPENPC_NOTIFICATION_ENDPOINT_RECIPIENT_V1',
      endpointId,
      channel: 'WEBHOOK',
      destinationRef,
    };
    const redaction: NotificationRoutingInstallation['redaction'] = {
      schema: 'OPENPC_EVIDENCE_EXPORT_NOTIFICATION_FIELDS_V1',
      allowedFields: ['checkpoint', 'evidenceExportId', 'outputDigest', 'recordCount'],
    };
    const installRoute = async (policyDigest: string) => {
      const profileId = id(),
        route = signNotificationClaim(
          'NotificationRoutingProfileV1',
          issuer.privateKey,
          issuer.spki,
          {
            ...scope,
            environmentId: pins.environmentId,
            profileId,
            revision: '1',
            validFromMs: now - 1000,
            validUntilMs: now + 3600000,
            sourceEvent: 'EvidenceExportCompleted',
            endpointId,
            endpointRevision: '2',
            signedChannelProfileDigest: trust.signedProfileDigest,
            templateDigest: sha256(template),
            recipientSetDigest: sha256(recipientSet),
            redactionProfileDigest: sha256(redaction),
            preferenceGeneration: '1',
            encryptionProfileDigest: notificationPayloadEncryptionProfileDigest,
            payloadKeyPolicyDigest: policyDigest,
            issuerKeyId: evidenceKeyId(issuer.spki),
          },
        );
      const value: NotificationRoutingInstallation = {
        trust: { ...trust, signedProfileDigest: sha256(route.cose) },
        signed: { payloadHex: route.payload.toString('hex'), coseHex: route.cose.toString('hex') },
        template,
        recipientSet,
        redaction,
        producerTrustDigest: pins.producerTrustDigest,
        installationReference: 'notification-custody-initial-routing',
      };
      await runScopedTransaction(
        input.installer,
        { ...scope, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
        id,
        (client) => installInitialNotificationRouting(client, value),
      );
      return { profileId, revision: '1', signedProfileDigest: value.trust.signedProfileDigest };
    };
    return {
      routing: await installRoute(pins.policyDigest),
      wrongPolicyRouting: await installRoute(sha256('different-custody-policy')),
      delivery: Object.freeze({
        credentialProvider: fixtures.credentialProvider,
        scope: Object.freeze({ ...scope, destinationRef }),
        credential: Object.freeze({ ...credential }),
        stats: () => notificationRuntimeDeliveryStats(fixtures, { ...scope, destinationRef }),
        withOutcome: <T>(
          outcome: 'DELIVERED' | 'RETRYABLE_NO_EFFECT' | 'PERMANENT_FAILURE' | 'AMBIGUOUS',
          use: () => Promise<T>,
        ) =>
          withNotificationRuntimeDeliveryOutcome(
            fixtures,
            { ...scope, destinationRef },
            outcome,
            use,
          ),
      }),
      close,
    };
  } catch (error) {
    try {
      await close();
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], 'Notification custody prerequisite failed');
    }
    throw error;
  }
}
