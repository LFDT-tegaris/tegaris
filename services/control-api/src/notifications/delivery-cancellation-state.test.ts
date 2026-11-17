import { validateNotificationRetryLineage } from './delivery-cancellation-contract.js';
import { notificationSignedOutcomeSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import { proposeNotificationDeliveryOutcome } from './delivery-outcome-contract.js';
import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
import { getTableConfig } from 'drizzle-orm/pg-core';
import {
  notificationDeliveryCancellations,
  notificationCancellationSigningAttempts,
} from './delivery-cancellation-schema.js';
import {
  admittedReceiptSchemaVersion,
  businessTransitionProfileForOperation,
  encodeAdmittedReceipt,
  signReceiptCose,
  signReceiptCoseV2,
  evidenceKeyId,
  signNotificationClaim,
  type BusinessTransitionReceipt,
  type NotificationDeliveryCancellationReceiptClaims,
} from '@openpc/security-kernel';
import { encodeCbor, decodeCbor } from '../../../../packages/security-kernel/src/canonical-cbor.js';
import { notificationDeliveryProviderSample } from '../../../../tests/integration/identity/notification-delivery-provider-cases.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  createNotificationCancellationReceiptRequest,
  validateNotificationCancellationReceiptRequest,
} from '../../../identity-service/src/domain/notification-cancellation-receipt-provider.js';
import type { NotificationReceiptProviderTrust } from '../../../identity-service/src/domain/notification-receipt-provider.js';
import { notificationCancellationSigningPurpose } from './receipt-signer-installation.js';
import {
  bindNotificationEndpointBusinessState,
  type NotificationEndpointBusinessState,
} from './endpoint-business-state.js';
import { notificationDeliveryStateDigest } from './delivery-start-contract.js';
import { notificationDeliverySnapshot } from './delivery-policy.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';
import {
  verifyNotificationDeliveryCancellationCause,
  NotificationDeliveryCancellationError,
  type NotificationCancellationCauseRow,
  decodeNotificationCancellationSigningRecord,
} from './delivery-cancellation-state.js';
import {
  proposeNotificationDeliveryCancellation,
  validateSignedNotificationDeliveryCancellation,
  encodeNotificationDeliveryCancellation,
  decodeNotificationDeliveryCancellation,
  NotificationDeliveryCancellationContractError,
} from './delivery-cancellation-contract.js';
const notificationDeliveryCancellationGuardsSql: string = (
  await import(new URL('./delivery-cancellation-guards.mjs', import.meta.url).href)
).notificationDeliveryCancellationGuardsSql;

const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (s: string) => sha256(Buffer.from(s));
const bytes = (s: string) => Buffer.from(s.slice(7), 'hex');
const profile = businessTransitionProfileForOperation('CFG-OP-UPDATE-NOTIFICATION-ENDPOINT')!;

/** Component cryptography/preimages only. These keys, assertions and records
 * are NOT installed SQL authority or a substitute for a public endpoint UPDATE.
 * The PG reader independently requires committed owners and consumed step-up. */
function causeFixture(scope?: {
  participantId: string;
  privacyDomainId: string;
  endpointId: string;
  endpointRevision: string;
}) {
  const q = {
    participantId: scope?.participantId ?? id(1),
    privacyDomainId: scope?.privacyDomainId ?? id(2),
    endpointId: scope?.endpointId ?? id(3),
    endpointRevision: scope?.endpointRevision ?? '2',
    causeOperationId: id(50),
  };
  const context = {
    ...q,
    aggregateId: q.endpointId,
    aggregateType: 'notification-endpoint',
    profileDigest: bytes(profile.profileDigest),
  };
  const before: NotificationEndpointBusinessState = {
    participantId: q.participantId,
    privacyDomainId: q.privacyDomainId,
    endpointId: q.endpointId,
    revision: q.endpointRevision,
    channel: 'WEBHOOK',
    state: q.endpointRevision === '1' ? 'DISABLED' : 'ACTIVE',
    destinationRef: `urn:openpc:resource:${id(4)}`,
    channelProfileDigest: h('channel'),
    credentialRef: `urn:openpc:resource:${id(5)}`,
    arbitraryEgress: false,
    candidateDigest: h('old-candidate'),
    verificationId: q.endpointRevision === '1' ? null : id(6),
  };
  const after: NotificationEndpointBusinessState = {
    ...before,
    revision: (BigInt(before.revision) + 1n).toString(),
    state: 'DISABLED',
    verificationId: null,
    candidateDigest: h('new-candidate'),
  };
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = pair.publicKey.export({ type: 'spki', format: 'der' }),
    key = pair.privateKey.export({ type: 'pkcs8', format: 'der' });
  const trust = Buffer.from('component-only-original-trust'),
    authority = Buffer.from('component-only-authority');
  const b = bindNotificationEndpointBusinessState(context, before),
    a = bindNotificationEndpointBusinessState(context, after);
  const receipt: BusinessTransitionReceipt = {
    receiptId: id(51),
    schemaDefinitionDigest: bytes(profile.schemaDefinitionDigest),
    transitionProfileId: profile.profileId,
    transitionProfileVersion: profile.profileVersion,
    transitionProfileDigest: bytes(profile.profileDigest),
    environmentId: 'test',
    participantId: q.participantId,
    privacyDomainId: q.privacyDomainId,
    operationId: q.causeOperationId,
    actionIntentId: profile.actionIntentId,
    catalogOperationId: profile.catalogOperationId,
    aggregateType: 'notification-endpoint',
    aggregateId: q.endpointId,
    actorKeyDigest: bytes(h('actor')),
    preCommitAuthorityDigest: bytes(sha256(authority)),
    actionIntentDigest: bytes(h('intent')),
    candidateDigest: bytes(h('complete-update-command')),
    idempotencyRecordId: id(52),
    before: b.reference,
    after: a.reference,
    authorizationEvidence: [
      { kind: 2, evidenceId: id(53), evidenceDigest: bytes(h('authorization')) },
      { kind: 4, evidenceId: id(54), evidenceDigest: bytes(h('step-up')) },
    ],
    outboxEvents: [
      {
        eventId: id(55),
        eventType: 'io.openpc.control.command.committed.v1',
        dataSchemaUri:
          'https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted',
        source: 'urn:openpc:service:control',
        subject: `urn:openpc:resource:${q.endpointId}`,
        aggregateSequence: 1n,
        occurredAtNs: 3100000000n,
        correlationId: q.causeOperationId,
        payloadDigest: bytes(h('outbox')),
      },
    ],
    transitionKind: 1,
    recordedAtNs: 3100000000n,
    signerId: evidenceKeyId(spki),
    signerTrustSnapshotDigest: bytes(sha256(trust)),
    requestDigest: bytes(h('request')),
  };
  const result = {
    operationId: receipt.operationId,
    resourceRef: `urn:openpc:resource:${q.endpointId}`,
    actionIntentId: receipt.actionIntentId,
    intentDigest: h('intent'),
    idempotencyKey: 'component-only-cause',
    state: 'SUCCEEDED',
    truthState: 'SUCCESS',
    createdAt: '1970-01-01T00:00:03.000000Z',
    updatedAt: '1970-01-01T00:00:03.100000Z',
    revision: after.revision,
  };
  function signed(r = receipt, beforePreimage = b.preimage, afterPreimage = a.preimage) {
    const payload = encodeAdmittedReceipt(r),
      version = admittedReceiptSchemaVersion(r);
    const row: NotificationCancellationCauseRow = {
      evidenceId: id(56),
      receiptId: r.receiptId,
      operationId: r.operationId,
      payload,
      payloadDigest: bytes(sha256(payload)),
      coseSign1: (version === 1 ? signReceiptCose : signReceiptCoseV2)(key, spki, payload),
      publicKey: spki,
      trustDigest: r.signerTrustSnapshotDigest,
      trustPreimage: trust,
      signerId: r.signerId,
      recordedAtNs: r.recordedAtNs.toString(),
      evidenceFormat: `COSE_SIGN1_24001_${version}_338`,
      beforePreimage,
      afterPreimage,
      authoritySnapshot: authority,
      resultPayload: result,
      resultDigest: bytes(sha256(result)),
    };
    return row;
  }
  return { q, before, after, receipt, result, context, signed, row: signed() };
}

it('verifies original signed endpoint UPDATE and exact replaced predecessor without reading a current endpoint', () => {
  const f = causeFixture(),
    cause = verifyNotificationDeliveryCancellationCause(f.row, f.q);
  expect(cause).toMatchObject({
    operationId: f.q.causeOperationId,
    endpointRevision: '2',
    successorRevision: '3',
    profileDigest: profile.profileDigest,
    receiptDigest: sha256(f.row.payload),
    beforeStateDigest: sha256(f.row.beforePreimage),
    afterStateDigest: sha256(f.row.afterPreimage),
  });
  expect(Object.isFrozen(cause)).toBe(true);
});
it.each([
  'participantId',
  'privacyDomainId',
  'endpointId',
  'causeOperationId',
  'endpointRevision',
] as const)('rejects foreign/mismatched cause selector %s', (field) => {
  const f = causeFixture();
  expect(() =>
    verifyNotificationDeliveryCancellationCause(f.row, {
      ...f.q,
      [field]: field === 'endpointRevision' ? '3' : id(99),
    }),
  ).toThrow(NotificationDeliveryCancellationError);
});
it.each([
  'beforePreimage',
  'afterPreimage',
  'authoritySnapshot',
  'payload',
  'coseSign1',
  'publicKey',
  'trustPreimage',
  'payloadDigest',
  'resultDigest',
] as const)('rejects original %s tampering', (field) => {
  const f = causeFixture(),
    data = Buffer.from(f.row[field]);
  data[data.length - 1] = data[data.length - 1]! ^ 1;
  expect(() =>
    verifyNotificationDeliveryCancellationCause({ ...f.row, [field]: data }, f.q),
  ).toThrow(NotificationDeliveryCancellationError);
});
it.each(['ACCEPTED', 'RUNNING', 'FAILED', 'WRITE_AMBIGUITY', 'ACKNOWLEDGED'])(
  'rejects %s even with a recomputed operation-result digest',
  (state) => {
    const f = causeFixture(),
      result = { ...f.result, state };
    expect(() =>
      verifyNotificationDeliveryCancellationCause(
        { ...f.row, resultPayload: result, resultDigest: bytes(sha256(result)) },
        f.q,
      ),
    ).toThrow(NotificationDeliveryCancellationError);
  },
);
it('rejects signed successor/preimage substitutions and non-UPDATE purpose rather than trusting a digest', () => {
  const f = causeFixture();
  for (const after of [
    { ...f.after, revision: '4' },
    { ...f.after, state: 'ACTIVE' as const, verificationId: id(60) },
    { ...f.after, candidateDigest: f.before.candidateDigest },
    { ...f.after, state: 'QUARANTINED' as const },
  ]) {
    const bound = bindNotificationEndpointBusinessState(f.context, after);
    const altered = {
      ...f.receipt,
      after: bound.reference,
      candidateDigest: bytes(after.candidateDigest),
    };
    const result = { ...f.result, revision: after.revision };
    expect(() =>
      verifyNotificationDeliveryCancellationCause(
        {
          ...f.signed(altered, f.row.beforePreimage, bound.preimage),
          resultPayload: result,
          resultDigest: bytes(sha256(result)),
        },
        f.q,
      ),
    ).toThrow(NotificationDeliveryCancellationError);
  }
  const raw = decodeCbor(f.row.beforePreimage) as unknown[];
  const projection = raw[8] as Map<number, unknown>;
  projection.set(99, 0n);
  expect(() =>
    verifyNotificationDeliveryCancellationCause(
      { ...f.row, beforePreimage: encodeCbor(raw as Parameters<typeof encodeCbor>[0]) },
      f.q,
    ),
  ).toThrow(NotificationDeliveryCancellationError);
  expect(() =>
    f.signed({ ...f.receipt, actionIntentId: 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1' }),
  ).toThrow();
});
it('preserves an authenticated quarantine replacement and rejects missing or substituted actor/step-up proofs', () => {
  const f = causeFixture(),
    before = { ...f.before, state: 'QUARANTINED' as const, verificationId: null },
    after = { ...f.after, state: 'QUARANTINED' as const };
  const b = bindNotificationEndpointBusinessState(f.context, before),
    a = bindNotificationEndpointBusinessState(f.context, after);
  expect(
    verifyNotificationDeliveryCancellationCause(
      f.signed({ ...f.receipt, before: b.reference, after: a.reference }, b.preimage, a.preimage),
      f.q,
    ).successorRevision,
  ).toBe('3');
  for (const evidence of [
    [],
    f.receipt.authorizationEvidence.slice(0, 1),
    [...f.receipt.authorizationEvidence].reverse(),
  ])
    expect(() =>
      verifyNotificationDeliveryCancellationCause(
        f.signed({ ...f.receipt, authorizationEvidence: evidence }),
        f.q,
      ),
    ).toThrow();
});

function cancellationFixture(started = false, retry = false) {
  const result = retry ? notificationSignedOutcomeSample('RETRYABLE_NO_EFFECT') : undefined;
  const resolved = result
    ? proposeNotificationDeliveryOutcome(result.value.input).after
    : undefined;
  const now = result ? result.value.receipt.recordedAtMs + 1 : 3500;
  const f = result?.f ?? notificationDeliveryProviderSample({ nowMs: 3000 }),
    start = f.original,
    source = start.source;
  const native = causeFixture(source),
    cause = verifyNotificationDeliveryCancellationCause(native.row, native.q);
  const worker = validateNotificationWorkerInstallation(start.workerInstallation, now);
  const before = {
    ...(resolved?.snapshot ?? (started ? start.after : start.before)),
    revision: resolved?.revision ?? (started ? '2' : '1'),
    deliveryRequestEventId: source.eventId,
    deliveryRequestOperationId: source.operationId,
    budgetEnvironmentId: source.environmentId,
    budgetGenerationId: id(70),
    budgetEffectiveDigest: h('generation'),
    budgetConfiguredLimit: 6,
    budgetWorkerInstallationDigest: worker.installationDigest,
  };
  const selector = {
    source: {
      worker: {
        participantId: source.participantId,
        privacyDomainId: source.privacyDomainId,
        installationDigest: worker.installationDigest,
      },
      notificationOccurrenceId: source.notificationOccurrenceId,
      eventId: source.eventId,
    },
    causeOperationId: cause.operationId,
    expectedRevision: before.revision,
  };
  const after = proposeNotificationDeliveryCancellation(
    before,
    {
      participantId: source.participantId,
      privacyDomainId: source.privacyDomainId,
      notificationOccurrenceId: source.notificationOccurrenceId,
      payloadDigest: source.payloadDigest,
      expectedRevision: before.revision,
    },
    now,
  );
  const receipt: NotificationDeliveryCancellationReceiptClaims = {
    environmentId: source.environmentId,
    participantId: source.participantId,
    privacyDomainId: source.privacyDomainId,
    receiptId: id(72),
    operationId: id(71),
    notificationOccurrenceId: source.notificationOccurrenceId,
    payloadDigest: source.payloadDigest,
    sourceEventId: source.eventId,
    sourceReceiptDigest: start.receipt.sourceReceiptDigest,
    workerProfileDigest: worker.input.pins.signedProfileDigest,
    routingProfileDigest: source.routingProfileDigest,
    authoritySnapshotDigest: start.workerAuthorityDigest,
    endpointId: source.endpointId,
    endpointRevision: source.endpointRevision,
    causeOperationId: cause.operationId,
    causeAction: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
    causeProfileDigest: cause.profileDigest,
    causeReceiptDigest: cause.receiptDigest,
    causeBeforeStateDigest: cause.beforeStateDigest,
    causeAfterStateDigest: cause.afterStateDigest,
    causeEndpointRevision: cause.successorRevision,
    deliveryRevision: before.revision,
    beforeStateDigest: notificationDeliveryStateDigest(
      notificationDeliverySnapshot.strip().parse(before),
      before.revision,
    ),
    afterStateDigest: notificationDeliveryStateDigest(
      notificationDeliverySnapshot.strip().parse(after),
      after.revision,
    ),
    beforeDeliveryState: retry ? 'RETRY_WAIT' : started ? 'STARTED' : 'PENDING',
    afterDeliveryState: retry ? 'CANCELLED' : started ? 'STARTED' : 'CANCELLED',
    attemptCount: before.attemptCount,
    disposition: retry
      ? 'PREVENT_LATER_ATTEMPTS'
      : started
        ? 'RECONCILE_ORIGINAL'
        : 'CANCELLED_BEFORE_START',
    recordedAtMs: now,
    signerKeyId: evidenceKeyId(f.signerSpki),
  };
  const sign = (claims = receipt) =>
    signNotificationClaim(
      'NotificationDeliveryCancellationReceiptV1',
      f.signerPrivateKey,
      f.signerSpki,
      claims,
    );
  const signed = sign();
  const transition = {
    schema: 'pc.notification.delivery-cancellation-transition.v1',
    selector,
    sourceOperationId: source.operationId,
    sourceReceiptDigest: receipt.sourceReceiptDigest,
    sourceClaims: source,
    workerInstallation: start.workerInstallation,
    workerAuthorityDigest: start.workerAuthorityDigest,
    cause,
    before,
    after,
    originalStart: started ? start : null,
    originalClaim:
      result?.f.claim ??
      (started ? { state: 'PENDING', claimToken: null, claimedAtMs: null } : null),
    ...(result ? { originalOutcome: result.value } : {}),
    receipt,
    payloadHex: signed.payload.toString('hex'),
    coseHex: signed.cose.toString('hex'),
  };
  return { transition, sign, fixture: f };
}
it.each([false, true])(
  'verifies canonical signed cancellation with original STARTED=%s; returns no dispatch capability',
  (started) => {
    const { transition } = cancellationFixture(started),
      encoded = encodeNotificationDeliveryCancellation(transition);
    expect(decodeNotificationDeliveryCancellation(encoded.bytes, encoded.digest)).toEqual(
      transition,
    );
    expect(encoded.transition.receipt.disposition).toBe(
      started ? 'RECONCILE_ORIGINAL' : 'CANCELLED_BEFORE_START',
    );
    expect(Object.isFrozen(encoded.transition)).toBe(true);
  },
);
it.each([
  'causeReceiptDigest',
  'causeBeforeStateDigest',
  'causeAfterStateDigest',
  'sourceReceiptDigest',
  'authoritySnapshotDigest',
  'beforeStateDigest',
  'afterStateDigest',
] as const)('rejects even correctly signed %s substitution against actual binding', (field) => {
  const f = cancellationFixture(),
    receipt = { ...f.transition.receipt, [field]: h('substitution') },
    signed = f.sign(receipt);
  expect(() =>
    validateSignedNotificationDeliveryCancellation({
      ...f.transition,
      receipt,
      payloadHex: signed.payload.toString('hex'),
      coseHex: signed.cose.toString('hex'),
    }),
  ).toThrow(NotificationDeliveryCancellationContractError);
});
it('rejects erased original STARTED/claim, signature tamper and noncanonical/unknown transport fields', () => {
  const { transition } = cancellationFixture(true);
  for (const altered of [
    { ...transition, originalStart: null },
    { ...transition, originalClaim: null },
    { ...transition, originalClaim: { state: 'UNKNOWN', claimToken: null, claimedAtMs: null } },
    {
      ...transition,
      coseHex: transition.coseHex.slice(0, -2) + (transition.coseHex.endsWith('00') ? '01' : '00'),
    },
    { ...transition, noEffect: true },
    { ...transition, before: { ...transition.before, cancelRequested: true } },
  ])
    expect(() => validateSignedNotificationDeliveryCancellation(altered)).toThrow(
      NotificationDeliveryCancellationContractError,
    );
  const encoded = encodeNotificationDeliveryCancellation(transition),
    different = Buffer.from(' ' + encoded.bytes.toString());
  expect(() => decodeNotificationDeliveryCancellation(different, sha256(different))).toThrow(
    NotificationDeliveryCancellationContractError,
  );
  const duplicate = Buffer.from(encoded.bytes.toString().replace('{', '{"schema":"ignored",'));
  expect(() => decodeNotificationDeliveryCancellation(duplicate, sha256(duplicate))).toThrow(
    NotificationDeliveryCancellationContractError,
  );
});
it('retains explicit SQL signer admission and independent projection/completion hooks without granting a new role or wire', () => {
  // Declaration preflight only; real SQL, crypto admission and race execution
  // remain the PG/runtime owner's obligations, not established by this check.
  expect(notificationDeliveryCancellationGuardsSql).toContain(
    'NOTIFICATION-CANCELLATION-SIGNER-UNBOUND',
  );
  expect(notificationDeliveryCancellationGuardsSql).toContain(
    'check_notification_delivery_cancellation_signer(uuid,text)',
  );
  expect(notificationDeliveryCancellationGuardsSql).toContain('FOR UPDATE');
  expect(notificationDeliveryCancellationGuardsSql).toContain('DEFERRABLE INITIALLY DEFERRED');
  expect(notificationDeliveryCancellationGuardsSql).not.toContain('GRANT ');
  expect(notificationDeliveryCancellationGuardsSql).not.toContain(
    'current_notification_delivery_limit',
  );
  expect(notificationDeliveryCancellationGuardsSql).not.toContain(
    'UPDATE control.notification_delivery_dispatch_intent',
  );
});

function signingFixture() {
  const f = cancellationFixture(),
    { coseHex, ...input } = f.transition;
  const worker = validateNotificationWorkerInstallation(input.workerInstallation, 3500),
    pins = worker.input.pins;
  const trust: NotificationReceiptProviderTrust = {
    worker: worker.input,
    signer: {
      owner: 'LS-NOTIFICATION' as const,
      purpose: notificationCancellationSigningPurpose,
      environmentId: pins.environmentId,
      participantId: pins.participantId,
      privacyDomainId: pins.privacyDomainId,
      installationId: id(91),
      workerInstallationDigest: worker.installationDigest,
      workerProfileDigest: pins.signedProfileDigest,
      workerIssuerSpkiHex: pins.issuerSpkiHex,
      principalId: pins.principalId,
      workloadCredentialId: pins.workloadCredentialId,
      workloadEpoch: pins.workloadEpoch,
      workloadId: pins.workloadId,
      secretClass: 'SECRET-SIGNING-KEY' as const,
      secretReference: 'secret://notification-component/cancellation#v1',
      secretVersion: 'v1',
      publicKeySpkiHex: f.fixture.signerSpki.toString('hex'),
      keyEpoch: '1',
      providerId: 'cancellation-component',
      providerOrigin: 'https://127.0.0.1:4433',
      providerTlsSpkiDigest: h('provider-tls'),
      validFromNs: String(worker.profile.validFromMs * 1000000),
      validUntilNs: String(worker.profile.validUntilMs * 1000000),
      installationReference: 'component-only',
    },
  };
  const request = createNotificationCancellationReceiptRequest(trust, {
    payloadHex: input.payloadHex,
    cancellationPreparationDigest: sha256(input),
  });
  const bound = validateNotificationCancellationReceiptRequest(request, trust);
  const preparation = { input, trust, request },
    preparation_bytes = Buffer.from(canonicalJson(preparation));
  const row = {
    preparation_bytes,
    preparation_digest: sha256(preparation_bytes),
    request_digest: bound.requestDigest,
    state: 'PREPARED',
    dispatch_token: null as string | null,
    dispatched_at_ms: null as string | null,
    observation_bytes: null as Buffer | null,
    observation_digest: null as string | null,
  };
  const observation = {
    schemaVersion: 1,
    providerId: request.providerId,
    signingAttemptId: request.signingAttemptId,
    requestDigest: bound.requestDigest,
    recordedAtMs: 3550,
    outcome: 'SIGNED',
    reason: null,
    coseHex,
  };
  return { row, preparation, observation };
}
it('retains the exact native cancellation signing request and first signature through PREPARED, DISPATCHED and OBSERVED readback', () => {
  const f = signingFixture();
  expect(decodeNotificationCancellationSigningRecord(f.row)).toMatchObject({
    state: 'PREPARED',
    dispatchToken: null,
    observation: null,
  });
  const dispatched = {
    ...f.row,
    state: 'DISPATCHED',
    dispatch_token: id(92),
    dispatched_at_ms: '3520',
  };
  expect(decodeNotificationCancellationSigningRecord(dispatched)).toMatchObject({
    state: 'DISPATCHED',
    dispatchToken: id(92),
    dispatchedAtMs: 3520,
    observation: null,
  });
  const bytes = Buffer.from(canonicalJson(f.observation));
  const observed = {
    ...dispatched,
    state: 'OBSERVED',
    observation_bytes: bytes,
    observation_digest: sha256(bytes),
  };
  const first = decodeNotificationCancellationSigningRecord(observed);
  expect(first.observation).toEqual(f.observation);
  expect(decodeNotificationCancellationSigningRecord(observed)).toEqual(first);
  expect(Object.isFrozen(first.preparation.request)).toBe(true);
});
it.each([
  'PREPARED_WITH_CLAIM',
  'DISPATCHED_WITHOUT_CLAIM',
  'NULL_DISPATCH_TIME',
  'BAD_TIME',
  'EARLY_TIME',
  'EXPIRED_TIME',
  'UNKNOWN_STATE',
  'OBSERVED_WITHOUT_RESULT',
  'WRONG_REQUEST_DIGEST',
])('rejects inconsistent retained signing state %s', (fault) => {
  const f = signingFixture(),
    row = { ...f.row };
  if (fault === 'PREPARED_WITH_CLAIM') row.dispatch_token = id(92);
  if (fault === 'DISPATCHED_WITHOUT_CLAIM') row.state = 'DISPATCHED';
  if (fault === 'NULL_DISPATCH_TIME') {
    row.state = 'DISPATCHED';
    row.dispatch_token = id(92);
  }
  if (['BAD_TIME', 'EARLY_TIME', 'EXPIRED_TIME'].includes(fault)) {
    row.state = 'DISPATCHED';
    row.dispatch_token = id(92);
    row.dispatched_at_ms =
      fault === 'BAD_TIME' ? '03520' : fault === 'EARLY_TIME' ? '3000' : '9999999999';
  }
  if (fault === 'UNKNOWN_STATE') row.state = 'UNKNOWN';
  if (fault === 'OBSERVED_WITHOUT_RESULT') {
    row.state = 'OBSERVED';
    row.dispatch_token = id(92);
    row.dispatched_at_ms = '3520';
  }
  if (fault === 'WRONG_REQUEST_DIGEST') row.request_digest = h('foreign');
  expect(() => decodeNotificationCancellationSigningRecord(row)).toThrow();
});
it('rejects receipt-purpose, preparation, signature and original-observation substitutions after recomputing outer hashes', () => {
  const f = signingFixture();
  const forged = {
    ...f.preparation,
    request: { ...f.preparation.request, method: 'SIGN_NOTIFICATION_DELIVERY_STARTED' },
  };
  const encoded = Buffer.from(canonicalJson(forged));
  expect(() =>
    decodeNotificationCancellationSigningRecord({
      ...f.row,
      preparation_bytes: encoded,
      preparation_digest: sha256(encoded),
    }),
  ).toThrow();
  for (const observation of [
    { ...f.observation, requestDigest: h('different') },
    { ...f.observation, recordedAtMs: 3510 },
    {
      ...f.observation,
      coseHex:
        f.observation.coseHex.slice(0, -2) + (f.observation.coseHex.endsWith('00') ? '01' : '00'),
    },
    { ...f.observation, outcome: 'REJECTED', reason: null, coseHex: null },
  ]) {
    const bytes = Buffer.from(canonicalJson(observation));
    expect(() =>
      decodeNotificationCancellationSigningRecord({
        ...f.row,
        state: 'OBSERVED',
        dispatch_token: id(92),
        dispatched_at_ms: '3520',
        observation_bytes: bytes,
        observation_digest: sha256(bytes),
      }),
    ).toThrow();
  }
});

it('keeps SQL request fields in sync with the actual closed Identity protocol and resolves declaration references', () => {
  const { preparation } = signingFixture();
  const match = notificationDeliveryCancellationGuardsSql.match(/q-ARRAY\[([^\]]+)\]/u);
  const keys = match![1]!.split(',').map((entry) => entry.trim().slice(1, -1));
  expect(keys.sort()).toEqual(Object.keys(preparation.request).sort());
  expect(notificationDeliveryCancellationGuardsSql).toContain(
    `jsonb_object_keys(q))<>${keys.length}`,
  );
  for (const table of [
    notificationDeliveryCancellations,
    notificationCancellationSigningAttempts,
  ]) {
    const config = getTableConfig(table);
    expect(config.enableRLS).toBe(true);
    for (const fk of config.foreignKeys)
      expect(fk.reference().foreignColumns.length).toBeGreaterThan(0);
  }
});

it('checks the native cancellation declaration through the shared SQL conditional preflight', () => {
  expect(() => verifyConditionCases(notificationDeliveryCancellationGuardsSql)).not.toThrow();
});

it('cancels RETRY_WAIT only with the original signed no-effect outcome and preserves that original', () => {
  const { transition } = cancellationFixture(true, true);
  const encoded = encodeNotificationDeliveryCancellation(transition);
  expect(encoded.transition.receipt.disposition).toBe('PREVENT_LATER_ATTEMPTS');
  expect(encoded.transition.after.state).toBe('CANCELLED');
  expect(encoded.transition.after.attemptCount).toBe(1);
  expect(decodeNotificationDeliveryCancellation(encoded.bytes, encoded.digest)).toEqual(transition);
  for (const originalOutcome of [
    undefined,
    null,
    notificationSignedOutcomeSample('AMBIGUOUS').value,
    notificationSignedOutcomeSample('DELIVERED').value,
  ]) {
    expect(() =>
      encodeNotificationDeliveryCancellation({ ...transition, originalOutcome }),
    ).toThrow(NotificationDeliveryCancellationContractError);
  }
  const altered = structuredClone(transition.originalOutcome!);
  altered.receipt.nextAttemptAtMs++;
  expect(() =>
    encodeNotificationDeliveryCancellation({ ...transition, originalOutcome: altered }),
  ).toThrow(NotificationDeliveryCancellationContractError);
});

it('preserves lowered/zero budgets while refusing stale or substituted retry originals', () => {
  const { transition } = cancellationFixture(true, true);
  const verify = (before: typeof transition.before) =>
    validateNotificationRetryLineage(
      transition.originalOutcome,
      before,
      transition.originalStart,
      transition.originalClaim,
    );
  expect(() =>
    verify({
      ...transition.before,
      attemptLimit: 0,
      revision: String(BigInt(transition.before.revision) + 1n),
    }),
  ).not.toThrow();
  for (const before of [
    { ...transition.before, revision: '1' },
    { ...transition.before, attemptLimit: transition.before.attemptLimit + 1 },
    { ...transition.before, cancelRequested: true },
    { ...transition.before, deliveryRequestEventId: id(999) },
    { ...transition.before, nextAttemptAtMs: transition.before.nextAttemptAtMs! + 1 },
  ])
    expect(() => verify(before)).toThrow();
});
