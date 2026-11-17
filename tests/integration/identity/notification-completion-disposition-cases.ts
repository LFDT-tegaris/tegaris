import { generateKeyPairSync } from 'node:crypto';
import { notificationCompletionDispositionClaims } from '../../../services/control-api/src/notifications/completion-disposition-contract.js';
import assert from 'node:assert/strict';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import {
  signNotificationClaim,
  type NotificationCompletionWorkerProfileClaims,
} from '../../../packages/security-kernel/src/notification-gateway/codec.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { validateNotificationCompletionWorkerOriginal } from '../../../services/control-api/src/notifications/completion-worker-installation-contract.js';
import { validateNotificationCompletionDispositionSignerInstallation } from '../../../services/control-api/src/notifications/completion-disposition-signer.js';
import {
  claimNotificationCompletionAttempt,
  consumeNotificationCompletionAttempt,
  finishNotificationCompletionAttempt,
  readNotificationCompletionOriginal,
  notificationCompletionSigningTransition,
  type NotificationCompletionSelector,
} from '../../../services/control-api/src/notifications/completion-disposition-state.js';
import type { IdentityKernel } from '../../../services/identity-service/src/domain/identity-kernel.js';
export const completionTestId = (n: number) =>
  `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
export const completionTestHash = (n: number): `sha256:${string}` =>
  `sha256:${n.toString(16).padStart(64, '0')}`;
/** Crypto fixtures only, not current TLS/SQL or effect admission. */
export function completionWorkerFixture(
  overrides: Partial<NotificationCompletionWorkerProfileClaims> = {},
) {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    spki = issuer.publicKey.export({ format: 'der', type: 'spki' });
  const profile: NotificationCompletionWorkerProfileClaims = {
    environmentId: 'test',
    participantId: completionTestId(1),
    privacyDomainId: completionTestId(2),
    profileId: completionTestId(3),
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 100000,
    serviceId: 'LS-CONTROL-WORK',
    processRole: 'ROLE-CONTROL-WORKER',
    subscriptionId: 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1',
    principalId: completionTestId(4),
    workloadCredentialId: completionTestId(5),
    workloadEpoch: '1',
    workloadId: 'control-work',
    workloadKeyDigest: completionTestHash(1),
    producerTrustDigest: completionTestHash(2),
    maximumAttempts: 3,
    initialBackoffMs: 100,
    maximumBackoffMs: 1000,
    issuerKeyId: sha256(spki),
    ...overrides,
  };
  const signed = signNotificationClaim(
    'NotificationCompletionWorkerProfileV1',
    issuer.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki,
    profile,
  );
  const pins = {
    environmentId: profile.environmentId,
    participantId: profile.participantId,
    privacyDomainId: profile.privacyDomainId,
    profileId: profile.profileId,
    revision: profile.revision,
    serviceId: profile.serviceId,
    processRole: profile.processRole,
    subscriptionId: profile.subscriptionId,
    principalId: profile.principalId,
    workloadCredentialId: profile.workloadCredentialId,
    workloadEpoch: profile.workloadEpoch,
    workloadId: profile.workloadId,
    workloadKeyDigest: profile.workloadKeyDigest,
    producerTrustDigest: profile.producerTrustDigest,
    issuerSpkiHex: spki.toString('hex'),
    signedProfileDigest: sha256(signed.cose),
  };
  return {
    profile,
    installation: {
      pins,
      signed: { payloadHex: signed.payload.toString('hex'), coseHex: signed.cose.toString('hex') },
      installationReference: 'completion-test',
    },
  };
}
export function completionJournalFixture() {
  const w = completionWorkerFixture(),
    worker = validateNotificationCompletionWorkerOriginal(w.installation);
  return {
    source: {
      participantId: w.profile.participantId,
      privacyDomainId: w.profile.privacyDomainId,
      eventId: completionTestId(20),
      envelopeDigest: completionTestHash(3),
      dataDigest: completionTestHash(4),
      partitionDigest: completionTestHash(5),
      receiptDigest: completionTestHash(6),
      producerTrustDigest: w.profile.producerTrustDigest,
    },
    initialWorker: w.installation,
    effectiveLimit: 3,
    attempts: [
      {
        attemptId: completionTestId(30),
        number: 1,
        workerInstallationDigest: worker.installationDigest,
        authorityDigest: completionTestHash(7),
        claimedAtMs: 1000,
        leaseUntilMs: 2000,
        state: 'FAILED' as const,
        finishedAtMs: 1100,
        nextAttemptAtMs: 1200,
      },
    ],
  };
}
export function completionDispositionFixture() {
  const journal = completionJournalFixture(),
    worker = validateNotificationCompletionWorkerOriginal(journal.initialWorker),
    key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const signer = {
    owner: 'LS-CONTROL-WORK',
    purpose: 'pc.cose.notification-completion-disposition-receipt.v1',
    environmentId: 'test',
    participantId: completionTestId(1),
    privacyDomainId: completionTestId(2),
    installationId: completionTestId(40),
    workerInstallationDigest: worker.installationDigest,
    workerProfileDigest: worker.input.pins.signedProfileDigest,
    workerIssuerSpkiHex: worker.input.pins.issuerSpkiHex,
    principalId: completionTestId(4),
    workloadCredentialId: completionTestId(5),
    workloadEpoch: '1',
    workloadId: 'control-work',
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://test-completion/receipt#v1',
    secretVersion: 'v1',
    publicKeySpkiHex: key.publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
    keyEpoch: '1',
    providerId: 'completion.test',
    providerOrigin: 'https://completion.test',
    providerTlsSpkiDigest: completionTestHash(99),
    validFromNs: '1000000000',
    validUntilNs: '100000000000',
    installationReference: 'test-completion',
  };
  return {
    journal,
    worker,
    signer,
    key,
    validatedSigner: validateNotificationCompletionDispositionSignerInstallation(signer),
  };
}
/** Plug into the existing real identity/PostgreSQL/TLS fixture after its actual
 * producer path returns a committed original event. No seeded intermediate
 * result, provider callback or fabricated admission is accepted by this helper.
 * This helper is one connected positive/replay/concurrency corpus, not full
 * quarantine/signing/restart acceptance; those need the canonical shared owner. */
export async function assertNotificationCompletionAttemptLifecycle(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
}) {
  const { pool, kernel, socket, selector } = input;
  const first = await claimNotificationCompletionAttempt(pool, kernel, socket, selector);
  assert.ok(first);
  const copied = { ...first };
  assert.throws(() => consumeNotificationCompletionAttempt(copied));
  const retained = consumeNotificationCompletionAttempt(first);
  assert.throws(() => consumeNotificationCompletionAttempt(first));
  const original = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.equal(original.journal?.journal.attempts.length, 1);
  assert.equal(original.journal?.journal.attempts[0]?.attemptId, retained.attempt.attemptId);
  const concurrent = await claimNotificationCompletionAttempt(pool, kernel, socket, selector);
  assert.equal(concurrent, null);
  const validated = await finishNotificationCompletionAttempt(
    pool,
    kernel,
    socket,
    selector,
    retained.attempt.attemptId,
  );
  assert.equal(validated.state, 'VALIDATED');
  const repeated = await finishNotificationCompletionAttempt(
    pool,
    kernel,
    socket,
    selector,
    retained.attempt.attemptId,
  );
  assert.deepEqual(repeated, validated);
  assert.equal(await claimNotificationCompletionAttempt(pool, kernel, socket, selector), null);
}
export function completionDispositionInputFixture(
  disposition: 'ADMITTED' | 'QUARANTINED' = 'ADMITTED',
) {
  const f = completionDispositionFixture();
  const journal = {
    ...f.journal,
    attempts:
      disposition === 'ADMITTED'
        ? [{ ...f.journal.attempts[0]!, state: 'VALIDATED' as const, nextAttemptAtMs: null }]
        : [
            f.journal.attempts[0]!,
            {
              ...f.journal.attempts[0]!,
              attemptId: completionTestId(31),
              number: 2,
              claimedAtMs: 1200,
              leaseUntilMs: 2200,
              finishedAtMs: 1300,
              nextAttemptAtMs: 1500,
            },
            {
              ...f.journal.attempts[0]!,
              attemptId: completionTestId(32),
              number: 3,
              claimedAtMs: 1500,
              leaseUntilMs: 2500,
              finishedAtMs: 1600,
              nextAttemptAtMs: 2000,
            },
          ],
  };
  const receiptId = completionTestId(50),
    operationId = completionTestId(51),
    before = {
      schema: 'pc.notification.completion-disposition-state.v1',
      journal,
      disposition: null,
    };
  const after = {
    ...before,
    disposition,
    receiptId,
    operationId,
    workItemKind: disposition === 'ADMITTED' ? 'NONE' : 'REMEDIATION',
    workItemId: receiptId,
    cursorMode: disposition === 'ADMITTED' ? 'ADVANCE' : 'HOLD',
  };
  return {
    ...f,
    input: {
      journal,
      workerInstallation: f.worker.input,
      signerInstallation: f.signer,
      metadata: {
        receiptId,
        operationId,
        authoritySnapshotDigest: completionTestHash(80),
        recordedAtMs: 3000,
        beforeStateDigest: sha256(before),
        afterStateDigest: sha256(after),
      },
      disposition,
      producerOutcome: disposition === 'ADMITTED' ? ('DELIVERED' as const) : null,
      producerWorkItemId: null,
    },
  };
}
/** Existing fixture supplies distinct real peers and a fresh original producer
 * event. Foreign/expired transport denials cannot create source state or work. */
export async function assertNotificationCompletionPeerDenials(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  expiredSocket: TLSSocket;
  selector: NotificationCompletionSelector;
  foreignSelector: NotificationCompletionSelector;
}) {
  const { pool, kernel, socket, expiredSocket, selector, foreignSelector } = input;
  assert.notEqual(foreignSelector.worker.privacyDomainId, selector.worker.privacyDomainId);
  const before = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  await assert.rejects(() =>
    claimNotificationCompletionAttempt(pool, kernel, socket, foreignSelector),
  );
  await assert.rejects(() =>
    claimNotificationCompletionAttempt(pool, kernel, expiredSocket, selector),
  );
  const after = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.deepEqual(after, before);
}
/** Capacity release is durable and has no signer/inbox/cursor/WorkItem effect.
 * Use a separate genuine source event, not another request ID for used intent. */
export async function assertNotificationCompletionBackpressure(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
}) {
  const { pool, kernel, socket, selector } = input;
  const cap = await claimNotificationCompletionAttempt(pool, kernel, socket, selector);
  assert.ok(cap);
  const c = consumeNotificationCompletionAttempt(cap);
  const result = await finishNotificationCompletionAttempt(
    pool,
    kernel,
    socket,
    selector,
    c.attempt.attemptId,
    true,
  );
  assert.equal(result.state, 'RELEASED');
  assert.notEqual(result.nextAttemptAtMs, null);
  const original = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.equal(original.journal?.journal.attempts.length, 1);
  assert.equal(original.signing, null);
  assert.equal(original.journal?.journal.attempts[0]?.state, 'RELEASED');
}
/** Real current TLS peer still cannot bypass native effect admission using SQL.
 * Each attempted mutation is rolled back even if a regression allows it. */
export async function assertNotificationCompletionDirectSqlDenials(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
}) {
  const { withNotificationCompletionWorkerPeer } =
    await import('../../../services/identity-service/src/domain/notification-completion-worker.js');
  const { pool, kernel, socket, selector } = input;
  const before = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.ok(before.journal);
  await withNotificationCompletionWorkerPeer(
    pool,
    kernel,
    socket,
    selector.worker,
    async (client) => {
      const statements = [
        'update control.notification_completion_source set effective_limit=effective_limit+1 where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
        'update control.notification_completion_attempt set attempt=attempt||\'{"state":"VALIDATED"}\'::jsonb where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and number=1',
        'delete from control.notification_completion_source where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
      ];
      for (const statement of statements) {
        await client.query('savepoint completion_direct_sql_negative');
        let rejected = false;
        try {
          await client.query(statement, [
            selector.worker.participantId,
            selector.worker.privacyDomainId,
            selector.eventId,
          ]);
        } catch {
          rejected = true;
        } finally {
          await client.query('rollback to savepoint completion_direct_sql_negative');
          await client.query('release savepoint completion_direct_sql_negative');
        }
        assert.equal(
          rejected,
          true,
          'Current peer SQL must not fabricate source budget, result or deletion',
        );
      }
    },
  );
  assert.deepEqual(
    await readNotificationCompletionOriginal(pool, kernel, socket, selector),
    before,
  );
}
/** After an actual unknown COMMIT, read one retained original and prove either
 * all terminal links or none. No resubmission or newly fabricated intent. */
export async function assertNotificationCompletionAtomicOriginal(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
}) {
  const { withNotificationCompletionWorkerPeer } =
    await import('../../../services/identity-service/src/domain/notification-completion-worker.js');
  const { pool, kernel, socket, selector } = input;
  const original = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.ok(original.signing);
  const signed = original.signing,
    receiptId = signed.preparation.request.signingAttemptId;
  return withNotificationCompletionWorkerPeer(
    pool,
    kernel,
    socket,
    selector.worker,
    async (client) => {
      const values = [
        selector.worker.participantId,
        selector.worker.privacyDomainId,
        selector.eventId,
      ];
      const disposition = await client.query<{
        disposition: string;
        cose_sign1: Buffer;
        receipt_id: string;
        operation_id: string;
      }>(
        'select disposition,cose_sign1,receipt_id::text,operation_id::text from control.notification_completion_disposition where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
        values,
      );
      const inbox = await client.query<{ state: string; admission_operation_id: string | null }>(
        "select state,admission_operation_id::text from control.notification_source_inbox where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'",
        values,
      );
      const cursor = await client.query(
        "select 1 from control.notification_source_cursor where participant_id=$1 and privacy_domain_id=$2 and last_event_id=$3 and subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'",
        values,
      );
      const work = await client.query<{ kind: string; resource_ref: string }>(
        'select kind,resource_ref from control.work_item where participant_id=$1 and privacy_domain_id=$2 and work_item_id=$3',
        [...values.slice(0, 2), receiptId],
      );
      if (disposition.rowCount === 0) {
        assert.equal(cursor.rowCount, 0);
        assert.equal(work.rowCount, 0);
        assert.ok(
          inbox.rowCount === 0 ||
            (inbox.rowCount === 1 &&
              inbox.rows[0]!.state === 'PENDING' &&
              inbox.rows[0]!.admission_operation_id === null),
        );
        return {
          state: 'NO_TERMINAL_EFFECT' as const,
          operationId: signed.preparation.request.operationId,
        };
      }
      assert.equal(disposition.rowCount, 1);
      const d = disposition.rows[0]!;
      assert.equal(d.receipt_id, receiptId);
      assert.equal(d.operation_id, signed.preparation.request.operationId);
      assert.equal(signed.state, 'OBSERVED');
      assert.equal(signed.observation?.outcome, 'SIGNED');
      assert.equal(d.cose_sign1.toString('hex'), signed.observation?.coseHex);
      assert.equal(inbox.rowCount, 1);
      assert.equal(inbox.rows[0]!.state, d.disposition);
      assert.equal(inbox.rows[0]!.admission_operation_id, d.operation_id);
      if (d.disposition === 'QUARANTINED') {
        assert.equal(cursor.rowCount, 0);
        assert.equal(work.rowCount, 1);
        assert.equal(work.rows[0]!.kind, 'REMEDIATION');
        assert.equal(work.rows[0]!.resource_ref, `urn:openpc:resource:${selector.eventId}`);
      } else {
        assert.equal(d.disposition, 'ADMITTED');
        assert.equal(cursor.rowCount, 1);
        assert.equal(work.rowCount, 0);
      }
      await client.query('select openpc.check_notification_completion_disposition_structure($1)', [
        selector.eventId,
      ]);
      await client.query('select openpc.check_notification_completion_disposition_original($1)', [
        selector.eventId,
      ]);
      return { state: 'ATOMIC_TERMINAL_EFFECT' as const, operationId: d.operation_id };
    },
  );
}
/** Use an authenticated original producer event whose semantic fault was installed
 * by the existing scoped negative fixture. This creates every consumer attempt
 * through its real owner; it never seeds exhaustion or grants remediation. */
export async function assertNotificationCompletionPoisonExhaustion(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
  signerInstallationDigest: string;
}) {
  const { prepareNotificationCompletionDisposition } =
    await import('../../../services/control-api/src/notifications/completion-disposition-state.js');
  const { notificationCompletionDispositionClaims } =
    await import('../../../services/control-api/src/notifications/completion-disposition-contract.js');
  const { pool, kernel, socket, selector } = input;
  const before = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.equal(before.journal, null);
  assert.equal(before.signing, null);
  const worker = validateNotificationCompletionWorkerOriginal(before.currentWorker),
    p = worker.profile;
  assert.ok(
    p.maximumAttempts <= 3 && p.maximumBackoffMs <= 1000,
    'Use bounded signed fixture inputs before allocating this case',
  );
  assert.ok(
    p.validUntilMs - Date.now() > p.maximumAttempts * (p.maximumBackoffMs + 2000),
    'Fresh authority must span the measured phase',
  );
  for (let number = 1; number <= p.maximumAttempts; number++) {
    const handle = await claimNotificationCompletionAttempt(pool, kernel, socket, selector);
    assert.ok(handle);
    const claim = consumeNotificationCompletionAttempt(handle);
    assert.equal(claim.attempt.number, number);
    const failed = await finishNotificationCompletionAttempt(
      pool,
      kernel,
      socket,
      selector,
      claim.attempt.attemptId,
    );
    assert.equal(failed.state, 'FAILED');
    if (number < p.maximumAttempts) {
      assert.notEqual(failed.nextAttemptAtMs, null);
      await new Promise((resolve) =>
        setTimeout(resolve, Math.max(0, failed.nextAttemptAtMs! - Date.now() + 1)),
      );
    }
  }
  const original = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.equal(original.journal?.journal.attempts.length, p.maximumAttempts);
  assert.equal(await claimNotificationCompletionAttempt(pool, kernel, socket, selector), null);
  const prepared = await prepareNotificationCompletionDisposition(pool, kernel, socket, {
    selector,
    signerInstallationDigest: input.signerInstallationDigest,
  });
  assert.ok(prepared);
  const claims = notificationCompletionDispositionClaims(prepared.preparation.preparation);
  assert.equal(claims.disposition, 'QUARANTINED');
  assert.equal(claims.attemptCount, p.maximumAttempts);
  assert.equal(claims.workItemKind, 'REMEDIATION');
  assert.equal(claims.cursorMode, 'HOLD');
  assert.equal(prepared.state, 'PREPARED');
  await assertNotificationCompletionAtomicOriginal(input);
  return prepared;
}
/** Existing real provider fixture induces the uncertain response; this helper
 * verifies lookup-only recovery from the original durable DISPATCHED journal.
 * Recreating this JS object is not a fresh-process/restart acceptance claim. */
export async function assertNotificationCompletionUnknownSigningLookup(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
  transport: { certificate: Buffer; privateKey: Buffer; trustCa: Buffer; timeoutMs?: number };
  expected: 'ABSENT' | 'SIGNED';
}) {
  const { NotificationCompletionDispositionRecovery } =
    await import('../../../services/control-api/src/notifications/completion-disposition-runtime.js');
  const { pool, kernel, socket, selector, transport } = input;
  const original = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.ok(original.signing);
  assert.equal(original.signing.state, 'DISPATCHED');
  const q = { ...selector, operationId: original.signing.preparation.request.operationId };
  const recovery = new NotificationCompletionDispositionRecovery(pool, kernel, transport),
    result = await recovery.reconcile(socket, q);
  if (input.expected === 'ABSENT') assert.equal(result.state, 'UNKNOWN');
  else {
    assert.equal(result.state, 'OBSERVED');
    if (result.state === 'OBSERVED') assert.equal(result.record.observation?.outcome, 'SIGNED');
  }
  const after = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.ok(after.signing);
  assert.deepEqual(after.signing.preparation, original.signing.preparation);
  assert.equal(after.signing.dispatchToken, original.signing.dispatchToken);
  assert.equal(after.signing.dispatchedAtMs, original.signing.dispatchedAtMs);
  const repeated = await new NotificationCompletionDispositionRecovery(
    pool,
    kernel,
    transport,
  ).reconcile(socket, q);
  assert.deepEqual(repeated, result);
  if (input.expected === 'ABSENT') {
    assert.equal(after.signing.state, 'DISPATCHED');
    assert.equal(after.signing.observation, null);
  }
}

/** Runs inside the existing genuine TLS callback, after exactly this phase was
 * admitted. No fixture row or surrogate admission is installed by this helper. */
export async function assertNotificationCompletionPhaseBindings(input: {
  client: PoolClient;
  eventId: string;
  phase: import('../../../services/identity-service/src/domain/notification-completion-worker.js').NotificationCompletionDispositionPhase;
  admission: import('../../../services/identity-service/src/domain/notification-completion-worker.js').NotificationCompletionWorkerAdmission;
}) {
  const { client, eventId, phase, admission } = input;
  const installation = admission.installation.installationDigest;
  const authority = admission.authorityDigest;
  const query = 'select openpc.check_notification_completion_effect_binding($1,$2,$3,$4)';
  await client.query(query, [eventId, phase, installation, authority]);
  const cases = [
    [eventId, null, installation, authority],
    [eventId, 'UNREGISTERED', installation, authority],
    [eventId, phase, null, authority],
    [eventId, phase, installation, null],
    [eventId, phase, sha256('foreign-worker'), authority],
    [eventId, phase, installation, sha256('foreign-authority')],
    [eventId, phase, 'bad', authority],
    [eventId, phase, installation, 'bad'],
    [completionTestId(999), phase, installation, authority],
  ];
  for (const values of cases) {
    await client.query('savepoint completion_binding_denial');
    let denied = false;
    try {
      await client.query(query, values);
    } catch (error) {
      const code = (error as { code?: string }).code;
      assert.ok(
        code === 'P0001' || code === 'P0002',
        'Denial must be a binding/admission rejection, not missing SQL or privileges',
      );
      denied = true;
    } finally {
      await client.query('rollback to savepoint completion_binding_denial');
      await client.query('release savepoint completion_binding_denial');
    }
    assert.ok(denied, 'Foreign or malformed binding must not consume current phase admission');
  }
  await client.query(query, [eventId, phase, installation, authority]);
}
/** Prepared real-owner case: caller first obtains an actual observed signer
 * result through the supported producer/attempt/provider owners. This neither
 * seeds an intermediate result nor claims that structural SQL verifies COSE. */
export async function assertNotificationCompletionTerminalCryptoClosed(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
}) {
  const { withNotificationCompletionWorkerPeer, admitNotificationCompletionDispositionPhase } =
    await import('../../../services/identity-service/src/domain/notification-completion-worker.js');
  const { pool, kernel, socket, selector } = input;
  const before = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.ok(before.signing);
  const encoded = notificationCompletionSigningTransition(before.signing),
    r = encoded.transition.receipt;
  await withNotificationCompletionWorkerPeer(
    pool,
    kernel,
    socket,
    selector.worker,
    async (client, admission) => {
      await admitNotificationCompletionDispositionPhase(
        admission,
        client,
        selector.worker,
        selector.eventId,
        'PUBLISH',
      );
      await client.query('savepoint completion_crypto_closed');
      let denied = false;
      try {
        await client.query(
          'insert into control.notification_completion_disposition(participant_id,privacy_domain_id,event_id,operation_id,receipt_id,disposition,transition,transition_bytes,transition_digest,receipt_payload,cose_sign1) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
          [
            selector.worker.participantId,
            selector.worker.privacyDomainId,
            selector.eventId,
            r.operationId,
            r.receiptId,
            r.disposition,
            encoded.transition,
            encoded.bytes,
            encoded.transitionDigest,
            encoded.payload,
            encoded.cose,
          ],
        );
      } catch (error) {
        assertNativeReceiptDenial(error);
        denied = true;
      } finally {
        await client.query('rollback to savepoint completion_crypto_closed');
        await client.query('release savepoint completion_crypto_closed');
      }
      assert.ok(denied, 'Phase identity alone must not authorize a receipt or terminal effects');
    },
  );
  assert.deepEqual(
    await readNotificationCompletionOriginal(pool, kernel, socket, selector),
    before,
  );
  assert.equal(
    (await assertNotificationCompletionAtomicOriginal(input)).state,
    'NO_TERMINAL_EFFECT',
  );
}

function assertNativeReceiptDenial(error: unknown) {
  const e = error as { code?: string; message?: string };
  assert.ok(
    e.code === 'P0002' ||
      (e.code === 'P0001' && /COMPLETION-(NATIVE|RECEIPT)/u.test(e.message ?? '')),
    'Expected native receipt or exact binding denial, not missing SQL, privileges or unrelated failure',
  );
}
async function expectReceiptSqlDenial(client: PoolClient, action: () => Promise<unknown>) {
  await client.query('savepoint completion_receipt_denial');
  let denied = false;
  try {
    await action();
  } catch (error) {
    assertNativeReceiptDenial(error);
    denied = true;
  } finally {
    await client.query('rollback to savepoint completion_receipt_denial');
    await client.query('release savepoint completion_receipt_denial');
  }
  assert.ok(denied, 'Receipt admission must reject absent, foreign or substituted proof');
}
/** The actual TLS/PG phase driver calls this before any signer result exists.
 * Valid phase identity cannot manufacture a non-null verified receipt. */
export async function assertNotificationCompletionPhaseOnlyReceiptDenied(
  client: PoolClient,
  eventId: string,
  phase: string,
) {
  for (const values of [
    [eventId, phase],
    [eventId, null],
    [completionTestId(999), phase],
  ]) {
    await expectReceiptSqlDenial(client, () =>
      client.query('select openpc.notification_completion_verified_receipt($1,$2)', values),
    );
  }
}
/** Prepared connected corpus: use the original observed response produced by
 * real owners. All adversarial writes roll back; no new signing intent or
 * intermediate business fixtures are created. Canonical runtime owns execution. */
export async function assertNotificationCompletionVerifiedReceiptBindings(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
}) {
  const { pool, kernel, socket, selector } = input;
  const {
    withNotificationCompletionWorkerPeer,
    admitNotificationCompletionDispositionPhase,
    admitNotificationCompletionDispositionReceipt,
  } =
    await import('../../../services/identity-service/src/domain/notification-completion-worker.js');
  const before = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.ok(before.signing?.observation?.outcome === 'SIGNED');
  assert.equal(
    (await assertNotificationCompletionAtomicOriginal(input)).state,
    'NO_TERMINAL_EFFECT',
  );
  const observation = before.signing.observation;
  assert.ok(observation.coseHex);
  const damaged = Buffer.from(observation.coseHex, 'hex');
  damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1;
  for (const phase of ['OBSERVE', 'PUBLISH'] as const) {
    await withNotificationCompletionWorkerPeer(
      pool,
      kernel,
      socket,
      selector.worker,
      async (client, admission) => {
        await admitNotificationCompletionDispositionPhase(
          admission,
          client,
          selector.worker,
          selector.eventId,
          phase,
        );
        await assertNotificationCompletionPhaseOnlyReceiptDenied(client, selector.eventId, phase);
        // Same closed COSE frame, payload and length, but altered ECDSA signature.
        for (const altered of [
          { ...observation, coseHex: damaged.toString('hex') },
          { ...observation, recordedAtMs: observation.recordedAtMs + 1 },
          { ...observation, requestDigest: sha256('substituted-request') },
        ]) {
          await assert.rejects(() =>
            admitNotificationCompletionDispositionReceipt(
              admission,
              client,
              selector.worker,
              selector.eventId,
              phase,
              altered,
            ),
          );
        }
        await client.query('savepoint verified_receipt');
        await admitNotificationCompletionDispositionReceipt(
          admission,
          client,
          selector.worker,
          selector.eventId,
          phase,
          observation,
        );
        const check = (event: string, p: string, ob: unknown) =>
          client.query('select openpc.check_notification_completion_receipt_admission($1,$2,$3)', [
            event,
            p,
            ob,
          ]);
        await check(selector.eventId, phase, observation);
        for (const altered of [
          { ...observation, coseHex: damaged.toString('hex') },
          { ...observation, recordedAtMs: observation.recordedAtMs + 1 },
          { ...observation, requestDigest: sha256('substituted-request') },
          { ...observation, verified: true },
        ]) {
          await expectReceiptSqlDenial(client, () => check(selector.eventId, phase, altered));
        }
        await expectReceiptSqlDenial(client, () =>
          check(completionTestId(999), phase, observation),
        );
        await expectReceiptSqlDenial(client, () =>
          check(selector.eventId, phase === 'OBSERVE' ? 'PUBLISH' : 'OBSERVE', observation),
        );
        await check(selector.eventId, phase, observation);
        if (phase === 'PUBLISH') {
          const encoded = notificationCompletionSigningTransition(before.signing!),
            r = encoded.transition.receipt;
          await client.query('savepoint incomplete_completion');
          let incomplete = false;
          try {
            // Exact authenticated terminal bytes alone cannot acknowledge the event.
            await client.query(
              'insert into control.notification_completion_disposition(participant_id,privacy_domain_id,event_id,operation_id,receipt_id,disposition,transition,transition_bytes,transition_digest,receipt_payload,cose_sign1) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
              [
                selector.worker.participantId,
                selector.worker.privacyDomainId,
                selector.eventId,
                r.operationId,
                r.receiptId,
                r.disposition,
                encoded.transition,
                encoded.bytes,
                encoded.transitionDigest,
                encoded.payload,
                encoded.cose,
              ],
            );
            try {
              await client.query('set constraints all immediate');
            } catch (error) {
              const e = error as { code?: string; message?: string };
              assert.ok(
                e.code === 'P0002' ||
                  (e.code === 'P0001' && /COMPLETION-ORIGINAL-/u.test(e.message ?? '')),
                'Expected incomplete durable publication rejection',
              );
              incomplete = true;
            }
          } finally {
            await client.query('rollback to savepoint incomplete_completion');
            await client.query('release savepoint incomplete_completion');
          }
          assert.ok(
            incomplete,
            'Terminal insertion must require atomic inbox/cursor/WorkItem effects',
          );
        }
        await client.query('rollback to savepoint verified_receipt');
        await client.query('release savepoint verified_receipt');
        await expectReceiptSqlDenial(client, () => check(selector.eventId, phase, observation));
        // Rollback removed SQL proof, not the immutable first result. A fresh
        // native verification may restore that same proof in this live callback.
        await admitNotificationCompletionDispositionReceipt(
          admission,
          client,
          selector.worker,
          selector.eventId,
          phase,
          observation,
        );
        await check(selector.eventId, phase, observation);
      },
    );
  }
  // A committed prior callback leaves no transferable receipt proof. Only a
  // fresh actual TLS transaction can acquire its own event/phase admission.
  await withNotificationCompletionWorkerPeer(
    pool,
    kernel,
    socket,
    selector.worker,
    async (client) => {
      for (const phase of ['OBSERVE', 'PUBLISH'])
        await expectReceiptSqlDenial(client, () =>
          client.query('select openpc.notification_completion_verified_receipt($1,$2)', [
            selector.eventId,
            phase,
          ]),
        );
    },
  );
  assert.deepEqual(
    await readNotificationCompletionOriginal(pool, kernel, socket, selector),
    before,
  );
  assert.equal(
    (await assertNotificationCompletionAtomicOriginal(input)).state,
    'NO_TERMINAL_EFFECT',
  );
}

/** Existing phase-only TLS case has no producer/signing state. These probes
 * prove absence of a direct-DML bypass; they are not positive journey coverage. */
export async function assertNotificationCompletionSharedDirectDenials(input: {
  client: PoolClient;
  eventId: string;
  admission: import('../../../services/identity-service/src/domain/notification-completion-worker.js').NotificationCompletionWorkerAdmission;
}) {
  const { client, eventId, admission } = input;
  const p = admission.installation.profile;
  const scope = [p.participantId, p.privacyDomainId];
  const envelope = Buffer.from('{}');
  const operations = [
    () =>
      client.query(
        `insert into control.notification_source_inbox(participant_id,privacy_domain_id,subscription_id,event_id,source,partition,source_sequence,data_digest,envelope_digest,envelope,state,admission_operation_id)
   values($1,$2,'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1',$3,'urn:openpc:service:LS-NOTIFICATION',$4,1,$5,$6,$7,'ADMITTED',$8)`,
        [
          ...scope,
          eventId,
          `urn:openpc:resource:${eventId}`,
          sha256('unadmitted'),
          sha256(envelope),
          envelope,
          completionTestId(998),
        ],
      ),
    () =>
      client.query(
        `insert into control.notification_source_cursor(participant_id,privacy_domain_id,subscription_id,source,partition,last_sequence,last_event_id,last_data_digest,revision)
   values($1,$2,'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1','urn:openpc:service:LS-NOTIFICATION',$3,1,$4,$5,1)`,
        [...scope, `urn:openpc:resource:${eventId}`, eventId, sha256('unadmitted')],
      ),
    ...['REMEDIATION', 'DELIVERY_FAILURE'].map(
      (kind) => () =>
        client.query(
          `insert into control.work_item(work_item_id,participant_id,privacy_domain_id,kind,state,resource_ref,payload_digest,reason,created_by_principal_id,row_version)
   values($1,$2,$3,$4,'OPEN',$5,$6,'Unadmitted',$7,1)`,
          [
            eventId,
            ...scope,
            kind,
            `urn:openpc:resource:${eventId}`,
            Buffer.alloc(32),
            p.principalId,
          ],
        ),
    ),
  ];
  for (const operation of operations) {
    await client.query('savepoint completion_shared_direct');
    let denied = false;
    try {
      await operation();
    } catch (error) {
      const code = (error as { code?: string }).code;
      assert.ok(
        code === 'P0001' || code === 'P0002',
        'Expected actual shared-owner denial, not missing SQL or privileges',
      );
      denied = true;
    } finally {
      await client.query('rollback to savepoint completion_shared_direct');
      await client.query('release savepoint completion_shared_direct');
    }
    assert.ok(denied, 'Phase-only admission must not fabricate inbox, cursor or WorkItem effects');
  }
  const count = await client.query<{ n: string }>(
    `select ((select count(*) from control.notification_source_inbox where participant_id=$1 and privacy_domain_id=$2 and event_id=$3)
  +(select count(*) from control.notification_source_cursor where participant_id=$1 and privacy_domain_id=$2 and last_event_id=$3)
  +(select count(*) from control.work_item where participant_id=$1 and privacy_domain_id=$2 and work_item_id=$3))::text n`,
    [...scope, eventId],
  );
  assert.equal(count.rows[0]?.n, '0');
}

/** Caller supplies an exclusively owned real pool with its existing private
 * native bridge, and an actual OBSERVED provider result. Only acknowledgement
 * after the real COMMIT is lost; identity, SQL and business effects stay real. */
export async function assertNotificationCompletionPublicationCommitLoss(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
  provider: { counters(): { performs: number; lookups: number; signatures: number } };
}) {
  const { pool, kernel, socket, selector, provider } = input;
  const { publishNotificationCompletionDisposition, NotificationCompletionDispositionUnknown } =
    await import('../../../services/control-api/src/notifications/completion-disposition-state.js');
  const original = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.equal(original.signing?.state, 'OBSERVED');
  assert.equal(original.signing?.observation?.outcome, 'SIGNED');
  assert.equal(
    (await assertNotificationCompletionAtomicOriginal(input)).state,
    'NO_TERMINAL_EFFECT',
  );
  const counters = provider.counters();
  const connect = pool.connect;
  let dropped = false;
  pool.connect = (async () => {
    const client = (await Reflect.apply(connect, pool, [])) as PoolClient;
    let inserted = false;
    return new Proxy(client, {
      get(actual, key) {
        if (key !== 'query') {
          const value = Reflect.get(actual, key, actual);
          return typeof value === 'function' ? value.bind(actual) : value;
        }
        return async (...args: unknown[]) => {
          const first = args[0],
            text = typeof first === 'string' ? first : ((first as { text?: string })?.text ?? '');
          const result = await Reflect.apply(actual.query, actual, args);
          if (/^insert into control\.notification_completion_disposition\(/iu.test(text.trim()))
            inserted = true;
          if (/^commit$/iu.test(text.trim()) && inserted && !dropped) {
            dropped = true;
            throw new Error('Injected lost completion COMMIT acknowledgement');
          }
          return result;
        };
      },
    }) as PoolClient;
  }) as Pool['connect'];
  try {
    await assert.rejects(
      () =>
        publishNotificationCompletionDisposition(pool, kernel, socket, {
          ...selector,
          operationId: original.signing!.preparation.request.operationId,
        }),
      NotificationCompletionDispositionUnknown,
    );
  } finally {
    pool.connect = connect;
  }
  assert.equal(dropped, true, 'The fault must follow an actual successful COMMIT');
  // Deliberately no repeat publication or signer dispatch after uncertainty.
  const recovered = await assertNotificationCompletionAtomicOriginal(input);
  assert.equal(recovered.state, 'ATOMIC_TERMINAL_EFFECT');
  assert.equal(recovered.operationId, original.signing!.preparation.request.operationId);
  assert.deepEqual(await assertNotificationCompletionAtomicOriginal(input), recovered);
  assert.deepEqual(
    (await readNotificationCompletionOriginal(pool, kernel, socket, selector)).signing,
    original.signing,
  );
  assert.deepEqual(provider.counters(), counters, 'Original lookup cannot sign or submit again');
}

/** Explicit idempotent publication replay on a separately completed case.
 * Original human WorkItem changes must be preserved by durable readback. */
export async function assertNotificationCompletionPublicationReplay(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
  provider: { counters(): { performs: number; lookups: number; signatures: number } };
}) {
  const { pool, kernel, socket, selector, provider } = input;
  const { publishNotificationCompletionDisposition } =
    await import('../../../services/control-api/src/notifications/completion-disposition-state.js');
  const { withNotificationCompletionWorkerPeer } =
    await import('../../../services/identity-service/src/domain/notification-completion-worker.js');
  const original = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.ok(original.signing);
  assert.equal(
    (await assertNotificationCompletionAtomicOriginal(input)).state,
    'ATOMIC_TERMINAL_EFFECT',
  );
  const snapshot = () =>
    withNotificationCompletionWorkerPeer(pool, kernel, socket, selector.worker, async (client) => {
      const result = await client.query<{ snapshot: unknown }>(
        `select jsonb_build_object(
   'terminal',(select to_jsonb(d) from control.notification_completion_disposition d where participant_id=$1 and privacy_domain_id=$2 and event_id=$3),
   'inbox',(select to_jsonb(i) from control.notification_source_inbox i where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'),
   'cursor',(select to_jsonb(c) from control.notification_source_cursor c join control.outbox_event e on e.participant_id=c.participant_id and e.privacy_domain_id=c.privacy_domain_id and c.source=e.source and c.partition='urn:openpc:resource:'||e.aggregate_id::text where c.participant_id=$1 and c.privacy_domain_id=$2 and e.event_id=$3 and c.subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'),
   'work',(select jsonb_agg(to_jsonb(w) order by work_item_id) from control.work_item w where participant_id=$1 and privacy_domain_id=$2 and work_item_id in ($3,$4))) snapshot`,
        [
          selector.worker.participantId,
          selector.worker.privacyDomainId,
          selector.eventId,
          original.signing!.preparation.request.signingAttemptId,
        ],
      );
      return result.rows[0]!.snapshot;
    });
  const before = await snapshot(),
    counters = provider.counters();
  const replay = await publishNotificationCompletionDisposition(pool, kernel, socket, {
    ...selector,
    operationId: original.signing.preparation.request.operationId,
  });
  assert.deepEqual(replay, notificationCompletionSigningTransition(original.signing).transition);
  assert.deepEqual(await snapshot(), before);
  assert.deepEqual(provider.counters(), counters);
  assert.equal(
    (await assertNotificationCompletionAtomicOriginal(input)).state,
    'ATOMIC_TERMINAL_EFFECT',
  );
}

/** A real SQL publication is allowed to finish, then an injected pre-COMMIT
 * failure must roll back its disposition, inbox, cursor and remediation together. */
export async function assertNotificationCompletionPublicationRollback(input: {
  pool: Pool;
  kernel: IdentityKernel;
  socket: TLSSocket;
  selector: NotificationCompletionSelector;
  provider: { counters(): { performs: number; lookups: number; signatures: number } };
}) {
  const { pool, kernel, socket, selector, provider } = input;
  const { publishNotificationCompletionDisposition, NotificationCompletionDispositionUnknown } =
    await import('../../../services/control-api/src/notifications/completion-disposition-state.js');
  const original = await readNotificationCompletionOriginal(pool, kernel, socket, selector);
  assert.ok(original.signing?.observation?.outcome === 'SIGNED');
  assert.equal(
    (await assertNotificationCompletionAtomicOriginal(input)).state,
    'NO_TERMINAL_EFFECT',
  );
  const counters = provider.counters(),
    connect = pool.connect;
  let failed = false;
  pool.connect = (async () => {
    const client = (await Reflect.apply(connect, pool, [])) as PoolClient;
    return new Proxy(client, {
      get(actual, key) {
        if (key !== 'query') {
          const value = Reflect.get(actual, key, actual);
          return typeof value === 'function' ? value.bind(actual) : value;
        }
        return async (...args: unknown[]) => {
          const first = args[0],
            text = typeof first === 'string' ? first : ((first as { text?: string })?.text ?? '');
          const result = await Reflect.apply(actual.query, actual, args);
          if (
            /^select openpc\.publish_notification_completion_disposition_effects\(/iu.test(
              text.trim(),
            ) &&
            !failed
          ) {
            failed = true;
            throw new Error('Injected failure after real completion effects and before COMMIT');
          }
          return result;
        };
      },
    }) as PoolClient;
  }) as Pool['connect'];
  try {
    await assert.rejects(
      () =>
        publishNotificationCompletionDisposition(pool, kernel, socket, {
          ...selector,
          operationId: original.signing!.preparation.request.operationId,
        }),
      NotificationCompletionDispositionUnknown,
    );
  } finally {
    pool.connect = connect;
  }
  assert.equal(failed, true, 'The fault must follow actual checked SQL publication');
  assert.equal(
    (await assertNotificationCompletionAtomicOriginal(input)).state,
    'NO_TERMINAL_EFFECT',
  );
  assert.deepEqual(
    (await readNotificationCompletionOriginal(pool, kernel, socket, selector)).signing,
    original.signing,
  );
  assert.deepEqual(provider.counters(), counters);
}

/** Genuine producer completion cases are fed only an event returned by the real
 * outcome publisher. The runner owns TLS, native bridge, pool and restart. */
export interface NotificationCompletionJourneyInput {
  readonly pool: Pool;
  readonly kernel: IdentityKernel;
  selector: NotificationCompletionSelector;
  signerInstallationDigest: string;
  transport: ConstructorParameters<
    typeof import('../../../services/control-api/src/notifications/completion-disposition-runtime.js').NotificationCompletionDispositionRecovery
  >[2];
  provider: { counters(): { performs: number; lookups: number; signatures: number } };
  withPeer<T>(run: (socket: TLSSocket) => Promise<T>): Promise<T>;
  /** Must close/reopen the real app and Pool and reinstall its native bridge. */
  reopen(): Promise<void>;
}
export type NotificationCompletionJourneyCase =
  | 'DELIVERED_REPLAY'
  | 'FAILED_HUMAN'
  | 'LEASE_EXHAUSTED'
  | 'PUBLICATION_ROLLBACK'
  | 'COMMIT_ACK_LOST';

export async function exerciseNotificationCompletionJourney(
  input: NotificationCompletionJourneyInput,
  kind: NotificationCompletionJourneyCase,
) {
  const {
    prepareNotificationCompletionDisposition,
    publishNotificationCompletionDisposition,
    NotificationCompletionDispositionUnknown,
  } =
    await import('../../../services/control-api/src/notifications/completion-disposition-state.js');
  const { NotificationCompletionDispositionRecovery } =
    await import('../../../services/control-api/src/notifications/completion-disposition-runtime.js');
  const q = input.selector;
  const before = await input.withPeer((socket) =>
    readNotificationCompletionOriginal(input.pool, input.kernel, socket, q),
  );
  assert.equal(
    before.journal,
    null,
    'Every independent case needs a distinct actual producer intent',
  );
  assert.equal(before.signing, null);
  const profile = validateNotificationCompletionWorkerOriginal(before.currentWorker).profile;
  assert.ok(
    profile.validUntilMs - Date.now() > 45000,
    'Fresh authority must outlive the unchanged 30-second attempt lease',
  );
  if (kind === 'LEASE_EXHAUSTED')
    assert.equal(
      profile.maximumAttempts,
      1,
      'Install the actual bounded signed profile before this case',
    );
  const concurrent = await Promise.allSettled(
    [0, 1].map(() =>
      input.withPeer((socket) =>
        claimNotificationCompletionAttempt(input.pool, input.kernel, socket, q),
      ),
    ),
  );
  const acquired = concurrent.filter(
    (r): r is PromiseFulfilledResult<object> => r.status === 'fulfilled' && r.value !== null,
  );
  assert.equal(acquired.length, 1, 'Exactly one claim may be issued');
  for (const result of concurrent)
    if (result.status === 'rejected')
      assert.ok(
        result.reason instanceof NotificationCompletionDispositionUnknown,
        'Unexpected concurrent claim failure',
      );
  const handle = acquired[0]!.value;
  assert.throws(() => consumeNotificationCompletionAttempt({ ...handle }));
  const claimed = consumeNotificationCompletionAttempt(handle);
  assert.throws(() => consumeNotificationCompletionAttempt(handle));
  if (kind === 'LEASE_EXHAUSTED') {
    const delay = claimed.attempt.leaseUntilMs - Date.now() + 10;
    assert.ok(delay > 0 && delay <= 30010);
    await new Promise((resolve) => setTimeout(resolve, delay));
    assert.ok(
      Date.now() < profile.validUntilMs,
      'Profile expiry cannot substitute for attempt exhaustion',
    );
  }
  const finished = await input.withPeer((socket) =>
    finishNotificationCompletionAttempt(
      input.pool,
      input.kernel,
      socket,
      q,
      claimed.attempt.attemptId,
    ),
  );
  assert.equal(finished.state, kind === 'LEASE_EXHAUSTED' ? 'FAILED' : 'VALIDATED');
  const prepared = await input.withPeer((socket) =>
    prepareNotificationCompletionDisposition(input.pool, input.kernel, socket, {
      selector: q,
      signerInstallationDigest: input.signerInstallationDigest,
    }),
  );
  assert.ok(prepared);
  const claims = notificationCompletionDispositionClaims(prepared.preparation.preparation);
  assert.equal(claims.disposition, kind === 'LEASE_EXHAUSTED' ? 'QUARANTINED' : 'ADMITTED');
  if (kind === 'LEASE_EXHAUSTED') {
    assert.equal(claims.cursorMode, 'HOLD');
    assert.equal(claims.workItemKind, 'REMEDIATION');
  }
  const counters = input.provider.counters();
  const signing = new NotificationCompletionDispositionRecovery(
    input.pool,
    input.kernel,
    input.transport,
  );
  const signingSelector = { ...q, operationId: prepared.preparation.request.operationId };
  const dispatched = await input.withPeer((socket) =>
    signing.dispatchOnce(socket, signingSelector),
  );
  const observed =
    dispatched.state === 'UNKNOWN'
      ? await input.withPeer((socket) => signing.reconcile(socket, signingSelector))
      : dispatched;
  assert.equal(
    observed.state,
    'OBSERVED',
    'Original completion signing remains UNKNOWN; lookup only',
  );
  if (observed.state !== 'OBSERVED') throw new Error('Completion original not observed');
  assert.equal(observed.record.observation?.outcome, 'SIGNED');
  assert.equal(input.provider.counters().performs - counters.performs, 1);
  assert.equal(input.provider.counters().signatures - counters.signatures, 1);
  const invoke = <T>(
    run: (
      args: Parameters<typeof assertNotificationCompletionAtomicOriginal>[0] & {
        provider: NotificationCompletionJourneyInput['provider'];
      },
    ) => Promise<T>,
  ) =>
    input.withPeer((socket) =>
      run({
        pool: input.pool,
        kernel: input.kernel,
        socket,
        selector: q,
        provider: input.provider,
      }),
    );
  if (kind === 'PUBLICATION_ROLLBACK') {
    await invoke(assertNotificationCompletionPublicationRollback);
  } else if (kind === 'COMMIT_ACK_LOST') {
    await invoke(assertNotificationCompletionPublicationCommitLoss);
  } else {
    await input.withPeer((socket) =>
      publishNotificationCompletionDisposition(input.pool, input.kernel, socket, signingSelector),
    );
    assert.equal(
      (await invoke(assertNotificationCompletionAtomicOriginal)).state,
      'ATOMIC_TERMINAL_EFFECT',
    );
    if (kind === 'DELIVERED_REPLAY') await invoke(assertNotificationCompletionPublicationReplay);
  }
  const original = await input.withPeer((socket) =>
    readNotificationCompletionOriginal(input.pool, input.kernel, socket, q),
  );
  const atomic = await invoke(assertNotificationCompletionAtomicOriginal),
    oldPool = input.pool,
    oldKernel = input.kernel,
    prior = input.provider.counters();
  await input.reopen();
  assert.notEqual(input.pool, oldPool, 'Restart requires a reopened Pool');
  assert.notEqual(input.kernel, oldKernel, 'Restart requires a reopened Identity repository');
  assert.deepEqual(
    await input.withPeer((socket) =>
      readNotificationCompletionOriginal(input.pool, input.kernel, socket, q),
    ),
    original,
  );
  assert.deepEqual(await invoke(assertNotificationCompletionAtomicOriginal), atomic);
  assert.deepEqual(input.provider.counters(), prior, 'Restart readback cannot sign or send');
  // The real native peer must deny a foreign scope without modifying the original.
  await assert.rejects(
    input.withPeer((socket) =>
      readNotificationCompletionOriginal(input.pool, input.kernel, socket, {
        ...q,
        worker: { ...q.worker, privacyDomainId: completionTestId(999) },
      }),
    ),
  );
  assert.deepEqual(await invoke(assertNotificationCompletionAtomicOriginal), atomic);
  return { signingSelector, atomic, original };
}

/** Initial profile/signer trust only. The producer event, attempts, signing
 * claims and terminal effects are always created by their supported owners. */
export async function createNotificationCompletionJourneyActor(input: {
  owner: Pool;
  controlWorker: unknown;
  directory: string;
  tls: {
    certificate: Buffer;
    privateKey: Buffer;
    server: { certificate: Buffer; privateKey: Buffer; ca: Buffer };
  };
}) {
  const { localOperationId: id } =
    await import('../../../services/identity-service/src/domain/local-operation-id.js');
  const { runScopedTransaction } =
    await import('../../../services/identity-service/src/db/scoped-transaction.js');
  const { validateNotificationWorkerInstallation } =
    await import('../../../services/control-api/src/notifications/worker-installation-contract.js');
  const { installInitialNotificationCompletionWorker, withdrawNotificationCompletionWorker } =
    await import('../../../services/control-api/src/notifications/completion-worker-installation.js');
  const {
    installInitialNotificationCompletionDispositionSigner,
    notificationCompletionDispositionSigningPurpose,
  } =
    await import('../../../services/control-api/src/notifications/completion-disposition-signer.js');
  const { createNotificationReceiptProviderFixture, notificationFixtureSpki } =
    await import('./notification-receipt-provider-fixture.js');
  const current = validateNotificationWorkerInstallation(input.controlWorker, Date.now()),
    p = current.profile;
  assert.equal(p.serviceId, 'LS-CONTROL-WORK');
  const now = Date.now();
  const worker = completionWorkerFixture({
    environmentId: p.environmentId,
    participantId: p.participantId,
    privacyDomainId: p.privacyDomainId,
    profileId: id(),
    principalId: p.principalId,
    workloadCredentialId: p.workloadCredentialId,
    workloadEpoch: p.workloadEpoch,
    workloadId: p.workloadId,
    workloadKeyDigest: current.input.pins.workloadKeyDigest,
    producerTrustDigest: p.producerTrustDigest,
    validFromMs: now - 1000,
    validUntilMs: now + 600000,
    maximumAttempts: 1,
  });
  const original = validateNotificationCompletionWorkerOriginal(worker.installation);
  const scope = { participantId: p.participantId, privacyDomainId: p.privacyDomainId };
  const install = <T>(run: (client: PoolClient) => Promise<T>) =>
    runScopedTransaction(
      input.owner,
      { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
      id,
      run,
    );
  const installationDigest = await install((client) =>
    installInitialNotificationCompletionWorker(client, worker.installation),
  );
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    key = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  const pins = {
    owner: 'LS-CONTROL-WORK' as const,
    purpose: notificationCompletionDispositionSigningPurpose,
    ...scope,
    environmentId: p.environmentId,
    installationId: id(),
    workerInstallationDigest: installationDigest,
    workerProfileDigest: original.input.pins.signedProfileDigest,
    workerIssuerSpkiHex: original.input.pins.issuerSpkiHex,
    principalId: p.principalId,
    workloadCredentialId: p.workloadCredentialId,
    workloadEpoch: p.workloadEpoch,
    workloadId: p.workloadId,
    secretClass: 'SECRET-SIGNING-KEY' as const,
    secretReference: 'secret://local/completion-journey#1',
    secretVersion: '1',
    publicKeySpkiHex: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
    keyEpoch: '1',
    providerId: 'completion-journey',
    providerOrigin: 'https://127.0.0.1:443',
    providerTlsSpkiDigest: sha256(notificationFixtureSpki(input.tls.server.certificate)),
    validFromNs: String(BigInt(worker.profile.validFromMs) * 1000000n),
    validUntilNs: String(BigInt(worker.profile.validUntilMs) * 1000000n),
    installationReference: 'genuine-completion-journey-initial-trust',
  };
  let provider: Awaited<ReturnType<typeof createNotificationReceiptProviderFixture>> | undefined;
  try {
    provider = await createNotificationReceiptProviderFixture({
      directory: input.directory,
      trust: { signer: pins, worker: worker.installation },
      signerPrivateKey: key,
      certificate: input.tls.server.certificate,
      privateKey: input.tls.server.privateKey,
      trustCa: input.tls.server.ca,
    });
    const signerInstallationDigest = await install((client) =>
      installInitialNotificationCompletionDispositionSigner(client, provider!.trust.signer),
    );
    return {
      worker: { ...scope, installationDigest },
      signerInstallationDigest,
      provider,
      transport: {
        certificate: input.tls.certificate,
        privateKey: input.tls.privateKey,
        trustCa: input.tls.server.ca,
      },
      withdraw: () =>
        install((client) =>
          withdrawNotificationCompletionWorker(client, { ...scope, installationDigest }),
        ),
      async close() {
        try {
          await provider!.close();
        } finally {
          key.fill(0);
        }
      },
    };
  } catch (error) {
    try {
      await provider?.close();
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], 'Completion actor cleanup failed');
    } finally {
      key.fill(0);
    }
    throw error;
  }
}
