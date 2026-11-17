import type { PoolClient } from 'pg';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { readIdentityEnvelopeRecoverySource } from './identity-envelope-recovery-source.js';
const owners = vi.hoisted(() => ({
  root: vi.fn(),
  signers: vi.fn(),
  session: vi.fn(),
  issuer: vi.fn(),
}));
vi.mock('./platform-envelope-scope.js', () => ({ readCurrentPlatformScope: owners.root }));
vi.mock('./platform-recovery-enrollment.js', () => ({
  assertPlatformRecoverySigners: owners.signers,
}));
vi.mock('./platform-recovery-proof.js', () => ({ readPlatformRecoverySession: owners.session }));
vi.mock('./identity-envelope-rotation-candidate.js', () => ({
  captureIdentityEnvelopeRotationSource: owners.issuer,
}));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const row = {
    document: f.enrollment,
    document_digest: Buffer.from(canonicalAuthorizationDigest(f.enrollment).slice(7), 'hex'),
    signature: Buffer.from(f.signed.signature, 'base64url'),
    state: 'ACTIVE',
    row_version: '1',
  };
  const pin = { document: f.trust, now: f.now, current: true, revision: '1' };
  const root = {
    ownerParticipantId: f.enrollment.participantId,
    installationPrivacyDomainId: f.enrollment.privacyDomainId,
    platformAuthorityDigest: f.enrollment.rootDigest,
    installationDigest: f.enrollment.installationDigest,
    environmentId: f.enrollment.installationEnvironmentId,
    grantable: {
      validFromNs: (BigInt(f.now.getTime()) * 1000000n).toString(),
      validUntilNs: (BigInt(Date.parse(f.enrollment.validUntil)) * 1000000n).toString(),
    },
  };
  const current = {
    issuer: {
      workloadPrincipalId: f.enrollment.issuerPrincipalId,
      workloadParticipantEpoch: '7',
      workloadPrincipalEpoch: '1',
      workloadCredentialEpoch: '1',
      workloadPublicKeyDigest: f.enrollment.issuerCredentialPublicKeyDigest,
      workloadCredentialId: f.enrollment.request.workloadCredentialId,
    },
    row: {
      trust_digest: Buffer.from(f.enrollment.oldTrustDigest.slice(7), 'hex'),
      admission_version: '1',
    },
    trust: {
      workloadParticipantEpoch: 1n,
      workloadPrincipalEpoch: 1n,
      workloadCredentialId: f.enrollment.request.workloadCredentialId,
      workloadCredentialEpoch: 1n,
    },
  };
  owners.root.mockResolvedValue(root);
  owners.issuer.mockResolvedValue(current);
  owners.session.mockResolvedValue({ sessionId: id(220), sessionEpoch: '1' });
  owners.signers.mockResolvedValue(undefined);
  const query = vi.fn(async (sql: string) => {
    if (sql.includes('from openpc.lock_identity_envelope_recovery_enrollment'))
      return { rowCount: 1, rows: [row] };
    if (sql.includes('identity_envelope_recovery_source_current'))
      return { rowCount: 1, rows: [pin] };
    throw Error('unexpected source query');
  });
  const client = { query } as unknown as PoolClient;
  const actor = {
    participantId: f.enrollment.participantId,
    principalId: f.enrollment.recoveryPrincipal.principalId,
    sessionToken: 'unit-only',
    platform: true,
  };
  return { ...f, row, pin, root, current, query, client, actor };
}
it('reads authentic custody and current source without writing authority', async () => {
  const f = fixture();
  const result = await readIdentityEnvelopeRecoverySource(
    f.client,
    f.actor,
    f.enrollment.enrollmentId,
    true,
  );
  expect(result.enrollment).toEqual(f.enrollment);
  expect(owners.session).toHaveBeenCalledWith(f.client, f.actor, f.enrollment);
  expect(owners.signers).toHaveBeenCalledWith(f.client, f.enrollment, true);
  expect(f.query.mock.calls.some(([sql]) => /^(insert|update|delete)/iu.test(sql))).toBe(false);
});
it.each([
  'revoked',
  'foreign-actor',
  'foreign-participant',
  'pin-stale',
  'bad-signature',
  'changed-root',
  'root-expired',
  'changed-issuer',
  'changed-selection',
  'current-trust',
  'lost-session',
  'lost-custodian',
  'qa-disabled',
])('denies %s without any source or authority mutation', async (failure) => {
  const f = fixture();
  if (failure === 'revoked') f.row.state = 'REVOKED';
  if (failure === 'foreign-actor') f.actor.principalId = f.enrollment.administratorPrincipalIds[0];
  if (failure === 'foreign-participant') f.actor.participantId = id(999);
  if (failure === 'pin-stale') f.pin.current = false;
  if (failure === 'bad-signature') f.row.signature = Buffer.alloc(64, 1);
  if (failure === 'changed-root') f.root.platformAuthorityDigest = 'sha256:' + '00'.repeat(32);
  if (failure === 'root-expired') f.root.grantable.validUntilNs = f.root.grantable.validFromNs;
  if (failure === 'changed-issuer') f.current.issuer.workloadPrincipalEpoch = '2';
  if (failure === 'changed-selection') f.current.row.admission_version = '2';
  if (failure === 'current-trust') f.current.trust.workloadParticipantEpoch = 7n;
  if (failure === 'lost-session') owners.session.mockRejectedValue(Error('lost session'));
  if (failure === 'lost-custodian') owners.signers.mockRejectedValue(Error('lost custodian'));
  await expect(
    readIdentityEnvelopeRecoverySource(
      f.client,
      f.actor,
      f.enrollment.enrollmentId,
      failure !== 'qa-disabled',
    ),
  ).rejects.toThrow();
  expect(f.query.mock.calls.some(([sql]) => /^(insert|update|delete)/iu.test(sql))).toBe(false);
});
