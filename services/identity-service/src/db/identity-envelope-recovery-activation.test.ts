import { createHash } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import { identityEnvelopeRecoveryIntent } from '../contracts/identity-envelope-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { PlatformRecoveryProof } from '../domain/platform-recovery-ceremony.js';
import { activateIdentityEnvelopeRecoveryLease } from './identity-envelope-recovery-activation.js';
const owner = vi.hoisted(() => ({ source: vi.fn(), issuer: vi.fn() }));
vi.mock('./identity-envelope-recovery-source.js', () => ({
  readIdentityEnvelopeRecoverySource: owner.source,
}));
vi.mock('./identity-envelope-rotation-issuer.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('./identity-envelope-rotation-issuer.js')>();
  return { ...original, captureIdentityEnvelopeRotationIssuer: owner.issuer };
});
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const issuer = {
    participantId: f.enrollment.participantId,
    privacyDomainId: f.enrollment.privacyDomainId,
    workloadCredentialId: f.enrollment.request.workloadCredentialId,
    workloadPrincipalId: f.enrollment.issuerPrincipalId,
    workloadParticipantEpoch: '7',
    workloadPrincipalEpoch: '1',
    workloadCredentialEpoch: '1',
    workloadPublicKeyDigest: f.enrollment.issuerCredentialPublicKeyDigest,
    credentialValidFromNs: (BigInt(f.now.getTime()) * 1000000n).toString(),
    credentialValidUntilNs: (BigInt(f.now.getTime() + 3600000) * 1000000n).toString(),
  };
  const intent = identityEnvelopeRecoveryIntent.parse({
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: f.enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(f.enrollment),
    rotationId: id(401),
    creationOperationId: id(402),
    sourceParticipantEpoch: '7',
    sourceIssuerPrincipalEpoch: '1',
    sourceIssuerCredentialEpoch: '1',
    oldTrustDigest: f.enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    postReviewRequired: true,
  });
  const proofs: PlatformRecoveryProof[] = [
    f.enrollment.recoveryPrincipal,
    ...f.enrollment.custodians,
  ].map((p, i) => ({
    ...p,
    proofId: id(600 + i),
    sessionId: id(610 + i),
    sessionEpoch: '1',
    phase: i === 0 ? 'REQUEST' : 'APPROVE',
    intentDigest: canonicalAuthorizationDigest(intent),
    verifiedAt: f.now,
  }));
  const proof: PlatformRecoveryProof = { ...proofs[0]!, proofId: id(603), phase: 'ACTIVATE' };
  const source = {
    enrollment: f.enrollment,
    enrollmentRevision: '1',
    now: f.now,
    issuer,
    root: { grantable: { validUntilNs: issuer.credentialValidUntilNs } },
  };
  owner.source.mockResolvedValue(source);
  owner.issuer.mockResolvedValue({ issuer: { ...issuer, workloadPrincipalEpoch: '2' } });
  const rows = [...proofs, proof].map((p) => ({
    proofId: p.proofId,
    digest: Buffer.alloc(32, 1),
    expiresAt: new Date(f.now.getTime() + 900000),
  }));
  const events: string[] = [];
  const query = vi.fn(async (sql: string) => {
    if (sql.includes('from control.platform_recovery_proof p'))
      return { rowCount: rows.length, rows };
    if (sql.includes('fence_identity_envelope_recovery_issuer')) {
      events.push('issuer-fence');
      return { rowCount: 1, rows: [{ epoch: '2' }] };
    }
    if (sql.startsWith('update control.platform_recovery_case')) {
      events.push('lease');
      return { rowCount: 1, rows: [] };
    }
    if (sql.startsWith('insert into control.outbox')) {
      events.push('outbox');
      return { rowCount: 1, rows: [] };
    }
    throw Error('unexpected query');
  });
  const signer = {
    signCanonicalAssertion: vi.fn(async (payload: Buffer) => {
      events.push('sign');
      return {
        evidenceCbor: payload,
        evidenceDigest: createHash('sha256').update(payload).digest(),
        coseSign1: Buffer.from('unit-only'),
        signerKeyDigest: Buffer.alloc(32, 1),
      };
    }),
    verifyCanonicalAssertion: vi.fn(async () => ({ signerKeyDigest: Buffer.alloc(32, 1) })),
  };
  const actor = {
    participantId: f.enrollment.participantId,
    principalId: f.enrollment.recoveryPrincipal.principalId,
    platform: true,
    sessionToken: 'unit-only',
  };
  const context = { enrollment: f.enrollment, intent, state: 'REQUESTED', proofs, now: f.now };
  const client = { query } as never;
  const activate = () =>
    activateIdentityEnvelopeRecoveryLease(client, actor, context, proof, id(700), signer, true);
  return {
    ...f,
    source,
    intent,
    proof,
    proofs,
    context,
    actor,
    rows,
    events,
    query,
    signer,
    activate,
  };
}
it('fences the affected issuer before signing one exact rotation lease, without ordinary authority rows', async () => {
  const f = fixture();
  const lease = await f.activate();
  expect(f.events).toEqual(['issuer-fence', 'sign', 'lease', 'outbox', 'outbox']);
  expect(lease).toMatchObject({
    rotationId: f.intent.rotationId,
    creationOperationId: f.intent.creationOperationId,
    issuer: { workloadPrincipalEpoch: '2', workloadCredentialEpoch: '1' },
    postReviewRequired: true,
  });
  expect(
    f.query.mock.calls.some(([sql]) =>
      /insert into control\.(assignment|authority_envelope|approval_request|business_signing_key)/u.test(
        sql,
      ),
    ),
  ).toBe(false);
});
it('uses the shortest governing session/source expiry without extending the proposal', async () => {
  const f = fixture();
  f.rows[1]!.expiresAt = new Date(f.now.getTime() + 45000);
  const lease = await f.activate();
  expect(Date.parse(lease.validUntil) - f.now.getTime()).toBe(45000);
  expect(f.intent.validUntil).toBe(new Date(f.now.getTime() + 900000).toISOString());
});
it.each([
  'missing-custodian',
  'duplicate-custodian',
  'stale-custodian',
  'future-activation',
  'pre-intent-activation',
  'invalid-activation-time',
  'stale-activation',
  'foreign-executor',
  'changed-source',
  'missing-stored-proof',
  'duplicate-stored-proof',
  'expired-session',
  'changed-issuer-capture',
])('rejects %s before lease publication', async (failure) => {
  const f = fixture();
  if (failure === 'missing-custodian') f.proofs.pop();
  if (failure === 'duplicate-custodian') f.proofs[2] = f.proofs[1]!;
  if (failure === 'stale-custodian')
    f.proofs[1] = { ...f.proofs[1]!, verifiedAt: new Date(f.now.getTime() - 300000) };
  if (failure === 'future-activation')
    Object.assign(f.proof, { verifiedAt: new Date(f.now.getTime() + 1) });
  if (failure === 'pre-intent-activation')
    Object.assign(f.proof, { verifiedAt: new Date(f.now.getTime() - 1) });
  if (failure === 'invalid-activation-time') Object.assign(f.proof, { verifiedAt: new Date(NaN) });
  if (failure === 'stale-activation')
    Object.assign(f.proof, { verifiedAt: new Date(f.now.getTime() - 300000) });
  if (failure === 'foreign-executor') f.actor.principalId = f.enrollment.custodians[0].principalId;
  if (failure === 'changed-source') f.source.issuer.workloadPrincipalEpoch = '2';
  if (failure === 'missing-stored-proof') f.rows.pop();
  if (failure === 'duplicate-stored-proof') f.rows[3] = f.rows[2]!;
  if (failure === 'expired-session') f.rows[2]!.expiresAt = f.now;
  if (failure === 'changed-issuer-capture')
    owner.issuer.mockResolvedValue({ issuer: { ...f.source.issuer, workloadPrincipalEpoch: '3' } });
  await expect(f.activate()).rejects.toThrow();
  expect(f.events).not.toContain('lease');
  expect(f.events).not.toContain('outbox');
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it('does not publish a lease or event after a mismatched signed payload; the caller must roll back the fence', async () => {
  const f = fixture();
  f.signer.signCanonicalAssertion.mockImplementation(async (payload) => ({
    evidenceCbor: Buffer.from('wrong'),
    evidenceDigest: createHash('sha256').update(payload).digest(),
    coseSign1: Buffer.from('unit-only'),
    signerKeyDigest: Buffer.alloc(32, 1),
  }));
  await expect(f.activate()).rejects.toThrow();
  expect(f.events).toEqual(['issuer-fence']);
});
