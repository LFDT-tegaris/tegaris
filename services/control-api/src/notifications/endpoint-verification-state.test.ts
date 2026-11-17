import { expect, it, vi } from 'vitest';
import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { NotificationCredentialLease } from '../../../identity-service/src/domain/notification-secret-recipient.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import type { MutationContext } from '../configuration/persistence/types.js';
import {
  NotificationEndpointVerificationState,
  assertNotificationAttemptContext,
  notificationVerificationIntentDigest,
} from './endpoint-verification-state.js';
import { notificationRequestAuthorityDigest } from './endpoint-admission.js';
const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = `sha256:${'1'.repeat(64)}`;
function fixture() {
  const input = {
    actionIntentId: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
    actionIntentDigest: hash,
    expectedRevision: '2',
    targetRef: `urn:openpc:resource:${id(3)}`,
    inputDigest: hash,
    reason: 'Verify this binding.',
  };
  const context = {
    authorization: {
      participantId: id(1),
      privacyDomainId: id(2),
      principalId: id(4),
      sessionId: id(5),
      sessionEpoch: '1',
    },
    candidate: input,
    resourceId: id(3),
    expectedRevision: '2',
    idempotencyKey: 'original-intent',
    actionIntentId: input.actionIntentId,
    actionIntentDigest: hash,
    catalogOperationId: 'CFG-OP-VERIFY-NOTIFICATION-ENDPOINT',
    aggregateType: 'notification-endpoint',
    resourceType: 'notification-endpoint',
    operationClass: 'UPDATE',
  } as unknown as MutationContext;
  const challenge = {
    version: 'NotificationVerificationChallengeV1',
    challengeId: id(6),
    nonce: 'aa'.repeat(32),
    environmentId: 'local',
    predecessor: {
      participantId: id(1),
      privacyDomainId: id(2),
      endpointId: id(3),
      revision: '2',
      channel: 'WEBHOOK',
      destinationRef: `urn:openpc:resource:${id(7)}`,
      channelProfileDigest: hash,
      credentialRef: `urn:openpc:resource:${id(8)}`,
    },
    resultRevision: '3',
    credential: {
      participantId: id(1),
      privacyDomainId: id(2),
      credentialRef: `urn:openpc:resource:${id(8)}`,
      channel: 'WEBHOOK',
      destinationRef: `urn:openpc:resource:${id(7)}`,
      secretClass: 'SECRET-NOTIFICATION-CREDENTIAL',
      owner: 'LS-NOTIFICATION',
      reference: 'secret://local/notification-mtls#1',
      version: '1',
      fingerprint: hash,
      epoch: '1',
      validFromMs: 1,
      validUntilMs: 2000,
      state: 'ACTIVE',
    },
    signedVerificationProfileDigest: hash,
    principalId: id(4),
    inputDigest: hash,
    businessIdempotencyDigest: notificationVerificationIntentDigest(context),
    issuedAtMs: 1000,
    expiresAtMs: 2000,
  };
  const row = {
    attempt_id: id(6),
    endpoint_id: id(3),
    principal_id: id(4),
    session_id: id(5),
    business_idempotency_digest: challenge.businessIdempotencyDigest,
    request_digest: sha256(input),
    authority_digest: notificationRequestAuthorityDigest(context),
    challenge_bytes: Buffer.from(canonicalJson({ challenge })),
    state: 'UNKNOWN' as const,
    response_bytes: null,
    verified_at_ms: null,
    receipt_digest: null,
    attached_operation_id: null,
  };
  return { context, row, challenge };
}
it('exact historical context comparison preserves expired original bytes without renewing authority', () => {
  const { context, row } = fixture(),
    original = Buffer.from(row.challenge_bytes);
  expect(() => assertNotificationAttemptContext(row, context)).not.toThrow();
  expect(row.challenge_bytes).toEqual(original);
  expect(row.state).toBe('UNKNOWN');
});
it('rejects changed actor/session/scope/idempotency/input/revision before observation attachment', () => {
  const { context, row } = fixture();
  for (const authorization of [
    { ...context.authorization, principalId: id(9) },
    { ...context.authorization, privacyDomainId: id(9) },
    { ...context.authorization, sessionId: id(9) },
    { ...context.authorization, sessionEpoch: '2' },
  ])
    expect(() => assertNotificationAttemptContext(row, { ...context, authorization })).toThrow();
  for (const change of [
    { resourceId: id(9) },
    { idempotencyKey: 'new-key' },
    { expectedRevision: '1' },
    { candidate: { ...(context.candidate as object), reason: 'different intent' } },
  ])
    expect(() => assertNotificationAttemptContext(row, { ...context, ...change })).toThrow();
});
it('does not accept copied correlation columns with changed challenge bytes', () => {
  const { context, row, challenge } = fixture();
  for (const change of [
    { principalId: id(9) },
    { inputDigest: `sha256:${'2'.repeat(64)}` },
    { challengeId: id(9) },
    { businessIdempotencyDigest: `sha256:${'3'.repeat(64)}` },
  ])
    expect(() =>
      assertNotificationAttemptContext(
        {
          ...row,
          challenge_bytes: Buffer.from(canonicalJson({ challenge: { ...challenge, ...change } })),
        },
        context,
      ),
    ).toThrow();
});

it('a fabricated TLS lease cannot allocate a dispatch transaction or change attempt state', async () => {
  const connect = vi.fn();
  const owner = new NotificationEndpointVerificationState(
    { connect } as unknown as Pool,
    {} as IdentityRuntimeVerifier,
  );
  const { context, row } = fixture();
  await expect(
    owner.dispatch(context, row.attempt_id, {} as NotificationCredentialLease, {
      signal: new AbortController().signal,
      timeoutMs: 1000,
    }),
  ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  expect(connect).not.toHaveBeenCalled();
  expect(row.state).toBe('UNKNOWN');
});
