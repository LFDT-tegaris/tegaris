import { generateKeyPairSync } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import { pendingExpiryPlatformRecoveryEnrollment } from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../domain/identity-runtime-crypto.js';
import { pendingExpiryPlatformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { closePlatformRecoveryCase } from './platform-recovery-closure.js';
import { readPlatformRecoveryApprovalContinuation } from './platform-recovery-approval-continuation.js';
import { readStoredPlatformRecoveryReceipt } from './platform-recovery-readback.js';

vi.mock('./platform-recovery-readback.js', () => ({ readStoredPlatformRecoveryReceipt: vi.fn() }));
beforeEach(() => vi.resetAllMocks());

async function fixture(state: 'REVOKED' | 'EXPIRED' = 'REVOKED', completeSession = true) {
  const f = pendingExpiryPlatformRecoveryFixture();
  const original = f.source.enrollment;
  if (original.schemaVersion !== 4) throw new Error('Expected expiry fixture');
  const key = generateKeyPairSync('ed25519');
  const publicKey = key.publicKey.export({ format: 'der', type: 'spki' });
  const crypto = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const closedAt = new Date(
    Date.parse(state === 'EXPIRED' ? f.intent.validUntil : f.intent.validFrom) + 1000,
  );
  let event: unknown[] = [];
  const closureClient = {
    query: vi.fn(async (sql: string, args: unknown[]) => {
      if (sql.startsWith('update control.platform_recovery_case'))
        return { rowCount: 1, rows: [{ state, revision: '4', now: closedAt }] };
      if (sql.startsWith('insert into control.outbox_aggregate_head'))
        return { rowCount: 1, rows: [{ sequence: '2' }] };
      if (sql.startsWith('insert into control.outbox_event')) {
        event = args;
        return { rowCount: 1, rows: [] };
      }
      throw new Error('Unexpected mutation');
    }),
  };
  // The actual session reader returns all four enumerable fields. The closure
  // owner signs that complete object, including the Date's canonical ISO value.
  const session = {
    sessionId: id(1800),
    sessionEpoch: '2',
    ...(completeSession
      ? { durationProfile: 'LOCAL_QA_10X', expiresAt: new Date(closedAt.getTime() + 3600000) }
      : {}),
  };
  const operationId = id(1801);
  await closePlatformRecoveryCase(
    closureClient as never,
    {
      participantId: original.participantId,
      principalId: original.recoveryPrincipal.principalId,
      platform: true,
      sessionToken: 'synthetic-test-session',
    },
    original,
    f.intent.recoveryId,
    '3',
    session,
    operationId,
    crypto,
  );
  const activationDigest = Buffer.alloc(32, 12);
  const witness = {
    schema: 'pc.identity.platform-prepare-approval-continuation' as const,
    schemaVersion: 1 as const,
    recoveryId: f.intent.recoveryId,
    intentDigest: canonicalAuthorizationDigest(f.intent),
    activationOperationId: id(1802),
    activationReceiptDigest: 'sha256:' + activationDigest.toString('hex'),
    candidateId: id(1803),
    approvalId: id(1804),
    candidateDigest: canonicalAuthorizationDigest(f.intent.preparation),
    businessKey: 'retained-initial-handoff-business-key',
    attempt: '1',
  };
  const enrollment = pendingExpiryPlatformRecoveryEnrollment.parse({
    ...original,
    enrollmentId: id(1805),
    validFrom: new Date(closedAt.getTime() + 1).toISOString(),
    validUntil: new Date(closedAt.getTime() + 600000).toISOString(),
    source: {
      ...original.source,
      closedApproval: {
        schema: 'pc.identity.closed-platform-approval-source',
        schemaVersion: 1,
        enrollmentId: original.enrollmentId,
        enrollmentDigest: canonicalAuthorizationDigest(original),
        approval: witness,
        closure: {
          eventId: event[4],
          evidenceDigest: 'sha256:' + (event[6] as Buffer).toString('hex'),
          operationId,
          state,
          revision: '4',
          actorPrincipalId: original.recoveryPrincipal.principalId,
          closedAt: closedAt.toISOString(),
          session: JSON.parse(JSON.stringify(session)),
        },
      },
    },
  });
  const receipt = {
    enrollment: original,
    activationEvidenceDigest: activationDigest,
    receipt: {
      intent: f.intent,
      state,
      revision: '4',
      authority: 'NONE',
      intentDigest: witness.intentDigest,
      activation: { operationId: witness.activationOperationId },
      proofs: Array.from({ length: 4 }, (_, n) => ({ proofId: id(1810 + n) })),
    },
  };
  vi.mocked(readStoredPlatformRecoveryReceipt).mockResolvedValue(receipt as never);
  const row = {
    evidenceCbor: event[5] as Buffer,
    evidenceDigest: event[6] as Buffer,
    cose: event[7] as Buffer,
    current: true,
  };
  const query = vi.fn(async () => ({ rowCount: 1, rows: [row] }));
  return {
    enrollment,
    original,
    row,
    receipt,
    query,
    read: () => readPlatformRecoveryApprovalContinuation({ query } as never, enrollment, crypto),
  };
}

it.each(['REVOKED', 'EXPIRED'] as const)(
  'authenticates the native %s closure and preserves original preparation',
  async (state) => {
    const f = await fixture(state),
      before = JSON.stringify(f.receipt);
    const result = await f.read();
    expect(result?.preparation).toEqual(f.receipt.receipt.intent.preparation);
    expect(result?.approvalContinuation).toEqual(f.enrollment.source.closedApproval!.approval);
    expect(f.enrollment.source.closedApproval!.closure.eventId).not.toBe(
      f.enrollment.source.closedApproval!.closure.operationId,
    );
    expect(JSON.stringify(f.receipt)).toBe(before);
    expect(f.query).toHaveBeenCalledOnce();
    expect(f.query.mock.calls[0]).toBeDefined();
  },
);

it.each([
  'native-denial',
  'signature',
  'payload',
  'closure-digest',
  'closure-session',
  'closure-operation',
  'closure-actor',
  'closure-revision',
  'old-enrollment',
  'custodian',
  'preparation',
  'duplicate-proof',
  'activation',
  'prior-continuation',
])('rejects %s before returning any receiving authority', async (fault) => {
  const f = await fixture(),
    closed = f.enrollment.source.closedApproval!;
  switch (fault) {
    case 'native-denial':
      f.row.current = false;
      break;
    case 'signature':
      f.row.cose = Buffer.alloc(f.row.cose.length);
      break;
    case 'payload':
      f.row.evidenceCbor = Buffer.from(f.row.evidenceCbor);
      f.row.evidenceCbor[5] = (f.row.evidenceCbor[5] ?? 0) ^ 1;
      break;
    case 'closure-digest':
      closed.closure.evidenceDigest = 'sha256:' + '00'.repeat(32);
      break;
    case 'closure-session':
      closed.closure.session.sessionEpoch = '3';
      break;
    case 'closure-operation':
      closed.closure.operationId = id(1900);
      break;
    case 'closure-actor':
      closed.closure.actorPrincipalId = f.original.custodians[0].principalId;
      break;
    case 'closure-revision':
      closed.closure.revision = '5';
      f.receipt.receipt.revision = '5';
      break;
    case 'old-enrollment':
      closed.enrollmentDigest = 'sha256:' + '00'.repeat(32);
      break;
    case 'custodian':
      f.enrollment.custodians[0].credentialEpoch = '8';
      break;
    case 'preparation':
      closed.approval.candidateDigest = 'sha256:' + '00'.repeat(32);
      break;
    case 'duplicate-proof':
      f.receipt.receipt.proofs[1] = f.receipt.receipt.proofs[0]!;
      break;
    case 'activation':
      closed.approval.activationOperationId = id(1901);
      break;
    case 'prior-continuation':
      f.receipt.receipt.intent.approvalContinuation = closed.approval;
      break;
  }
  await expect(f.read()).rejects.toThrow();
});

it('rejects unknown source fields and self-enrollment before installation', async () => {
  const f = await fixture();
  expect(
    pendingExpiryPlatformRecoveryEnrollment.safeParse({
      ...f.enrollment,
      source: { ...f.enrollment.source, bypass: true },
    }).success,
  ).toBe(false);
  f.enrollment.source.closedApproval!.enrollmentId = f.enrollment.enrollmentId;
  expect(pendingExpiryPlatformRecoveryEnrollment.safeParse(f.enrollment).success).toBe(false);
});

it('preserves historical two-field closure session evidence', async () => {
  const f = await fixture('REVOKED', false);
  expect((await f.read())?.approvalContinuation).toEqual(
    f.enrollment.source.closedApproval!.approval,
  );
});

it.each(['durationProfile', 'expiresAt'] as const)(
  'rejects altered signed session %s',
  async (field) => {
    const f = await fixture();
    const session = f.enrollment.source.closedApproval!.closure.session;
    if (!('durationProfile' in session)) throw new Error('Expected complete session preimage');
    if (field === 'durationProfile') session.durationProfile = 'C17';
    else session.expiresAt = new Date(Date.parse(session.expiresAt) + 1).toISOString();
    await expect(f.read()).rejects.toThrow('Platform recovery unavailable');
  },
);
