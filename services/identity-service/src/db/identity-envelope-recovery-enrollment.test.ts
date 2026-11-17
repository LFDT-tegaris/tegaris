import { sign } from 'node:crypto';
import type { PoolClient } from 'pg';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { identityEnvelopeRecoveryFixture } from '../domain/identity-envelope-recovery.test-fixture.js';
import { identityEnvelopeRecoveryCustodyPreimage } from '../domain/identity-envelope-recovery-custody.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { writeRecoveryDiagnostic } from '../platform-recovery-diagnostics.js';
import {
  installIdentityEnvelopeRecoveryReceivingTrust,
  enrollIdentityEnvelopeRecovery,
} from './identity-envelope-recovery-enrollment.js';

const owners = vi.hoisted(() => ({ root: vi.fn(), signers: vi.fn(), issuer: vi.fn() }));
vi.mock('./platform-envelope-scope.js', () => ({ readCurrentPlatformScope: owners.root }));
vi.mock('./platform-recovery-enrollment.js', () => ({
  assertPlatformRecoverySigners: owners.signers,
}));
vi.mock('./identity-envelope-rotation-candidate.js', () => ({
  captureIdentityEnvelopeRotationSource: owners.issuer,
}));
vi.mock('../platform-recovery-diagnostics.js', () => ({ writeRecoveryDiagnostic: vi.fn() }));
beforeEach(() => vi.resetAllMocks());

function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const root = {
    platformContextId: f.enrollment.platformContextId,
    ownerParticipantId: f.enrollment.participantId,
    installationPrivacyDomainId: f.enrollment.privacyDomainId,
    environmentId: f.enrollment.installationEnvironmentId,
    installationDigest: f.enrollment.installationDigest,
    platformAuthorityEpoch: f.enrollment.rootEpoch,
    platformAuthorityDigest: f.enrollment.rootDigest,
    grantable: { validFromNs: '1791003600000000000', validUntilNs: '1791028800000000000' },
  };
  // Use the fixture's independently fixed clock, rather than today's host time.
  root.grantable.validFromNs = (BigInt(Date.parse(f.trust.validFrom)) * 1000000n).toString();
  root.grantable.validUntilNs = (BigInt(Date.parse(f.trust.validUntil)) * 1000000n).toString();
  const installation = {
    installation: { pins: { profile: 'local' } },
    bytes: Buffer.from('{"pins":{"profile":"local"}}'),
    digest: f.trust.installationDigest,
    profile: 'local',
    sourceAuthenticated: true,
    now: f.now,
    rootRevision: '1',
    pending: false,
  };
  const source = {
    issuer: {
      workloadPrincipalId: f.enrollment.issuerPrincipalId,
      workloadParticipantEpoch: '7',
      workloadPrincipalEpoch: '1',
      workloadCredentialEpoch: '1',
      workloadPublicKeyDigest: f.enrollment.issuerCredentialPublicKeyDigest,
      workloadCredentialId: f.enrollment.request.workloadCredentialId,
      credentialValidUntilNs: root.grantable.validUntilNs,
    },
    trust: {
      workloadParticipantEpoch: 1n,
      workloadPrincipalEpoch: 1n,
      workloadCredentialId: f.enrollment.request.workloadCredentialId,
      workloadCredentialEpoch: 1n,
    },
    row: {
      trust_digest: Buffer.from(f.enrollment.oldTrustDigest.slice(7), 'hex'),
      admission_version: '1',
    },
  };
  owners.root.mockResolvedValue(root);
  owners.signers.mockResolvedValue(undefined);
  owners.issuer.mockResolvedValue(source);
  const facts = {
    owner: true,
    pinState: 'ACTIVE',
    pinVersion: '1',
    forbidden: false,
    enrollmentState: 'ACTIVE',
  };
  const query = vi.fn(async (sql: string) => {
    if (sql.includes("current_user='openpc_control_owner'"))
      return { rows: [{ permitted: facts.owner }], rowCount: 1 };
    if (sql.includes('from control.operations_installation'))
      return { rows: [installation], rowCount: 1 };
    if (
      sql.startsWith('select document') &&
      sql.includes('identity_envelope_recovery_custody_trust')
    )
      return {
        rows: [
          {
            document: f.trust,
            digest: Buffer.from(canonicalAuthorizationDigest(f.trust).slice(7), 'hex'),
            state: facts.pinState,
            revision: facts.pinVersion,
          },
        ],
        rowCount: 1,
      };
    if (sql.includes('select exists'))
      return { rows: [{ forbidden: facts.forbidden }], rowCount: 1 };
    if (sql.startsWith('select document') && sql.includes('identity_envelope_recovery_enrollment'))
      return {
        rows: [
          {
            document: f.enrollment,
            digest: Buffer.from(canonicalAuthorizationDigest(f.enrollment).slice(7), 'hex'),
            signature: Buffer.from(f.signed.signature, 'base64url'),
            state: facts.enrollmentState,
            revision: '1',
          },
        ],
        rowCount: 1,
      };
    if (sql.startsWith('insert into control.identity_envelope_recovery_'))
      return { rows: [], rowCount: 1 };
    throw new Error('Unexpected owner SQL');
  });
  const client = { query } as unknown as PoolClient;
  return { ...f, root, installation, source, facts, query, client };
}

describe('signed initial custody owner without business authority', () => {
  it('installs receiving public trust only and preserves its exact digest', async () => {
    const f = fixture();
    const result = await installIdentityEnvelopeRecoveryReceivingTrust(f.client, f.trust, {
      localQaEnabled: true,
    });
    expect(result).toEqual({
      custodyTrustId: f.trust.custodyTrustId,
      digest: canonicalAuthorizationDigest(f.trust),
      state: 'INSTALLED',
      authority: 'NONE',
    });
    expect(f.query.mock.calls.filter(([sql]) => sql.startsWith('insert'))).toHaveLength(1);
    expect(owners.signers).not.toHaveBeenCalled();
    expect(owners.issuer).not.toHaveBeenCalled();
  });
  it('enrolls exact signed custody while installation and issuer environment names remain distinct', async () => {
    const f = fixture();
    expect(f.enrollment.installationEnvironmentId).not.toBe(f.enrollment.request.environmentId);
    const result = await enrollIdentityEnvelopeRecovery(f.client, f.signed, {
      localQaEnabled: true,
    });
    expect(result.authority).toBe('NONE');
    expect(
      f.query.mock.invocationCallOrder.find((_, index) =>
        f.query.mock.calls[index]?.[0].startsWith('insert'),
      ),
    ).toBeLessThan(owners.signers.mock.invocationCallOrder[0]!);
    expect(result.digest).toBe(canonicalAuthorizationDigest(f.enrollment));
    const writes = f.query.mock.calls.filter(([sql]) => /^(insert|update|delete)/iu.test(sql));
    expect(writes).toHaveLength(1);
    expect(writes[0]![0]).toContain('insert into control.identity_envelope_recovery_enrollment');
    expect(writes[0]![0]).not.toMatch(
      /(assignment|authority_envelope|recovery_case|signing_key_rotation)/u,
    );
  });
  it('keeps the original valid signature on replay instead of overwriting evidence', async () => {
    const f = fixture();
    const signature = sign('sha256', identityEnvelopeRecoveryCustodyPreimage(f.enrollment), {
      key: f.key.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    await enrollIdentityEnvelopeRecovery(
      f.client,
      { document: f.enrollment, signature },
      { localQaEnabled: true },
    );
    expect(f.query.mock.calls.some(([sql]) => sql.startsWith('update'))).toBe(false);
    expect(f.query.mock.calls.find(([sql]) => sql.startsWith('insert'))?.[0]).toContain(
      'on conflict(enrollment_id) do nothing',
    );
  });
  it.each([
    'owner',
    'source-authentication',
    'installation-bytes',
    'profile',
    'pending-root',
    'revoked-pin',
    'changed-root',
    'changed-issuer',
    'changed-selection',
    'expired-issuer',
    'ordinary-executor',
    'current-trust',
    'custodian-credential',
    'signature',
  ])('rejects %s without retaining provisional custody or granting authority', async (failure) => {
    const f = fixture();
    if (failure === 'owner') f.facts.owner = false;
    if (failure === 'source-authentication') f.installation.sourceAuthenticated = false;
    if (failure === 'installation-bytes')
      f.installation.bytes = Buffer.from('unsigned replacement');
    if (failure === 'profile') f.installation.profile = 'production';
    if (failure === 'pending-root') f.installation.pending = true;
    if (failure === 'revoked-pin') f.facts.pinState = 'REVOKED';
    if (failure === 'changed-root') f.root.platformAuthorityEpoch = '2';
    if (failure === 'changed-issuer') f.source.issuer.workloadPrincipalEpoch = '2';
    if (failure === 'changed-selection') f.source.row.admission_version = '2';
    if (failure === 'expired-issuer')
      f.source.issuer.credentialValidUntilNs = (BigInt(f.now.getTime()) * 1000000n).toString();
    if (failure === 'ordinary-executor') f.facts.forbidden = true;
    if (failure === 'current-trust') f.source.trust.workloadParticipantEpoch = 7n;
    if (failure === 'custodian-credential')
      owners.signers.mockRejectedValue(new Error('unavailable signer'));
    if (failure === 'signature') f.signed.signature = Buffer.alloc(64, 1).toString('base64url');
    await expect(
      enrollIdentityEnvelopeRecovery(f.client, f.signed, { localQaEnabled: true }),
    ).rejects.toThrow();
    const sourceFailure = [
      'changed-issuer',
      'changed-selection',
      'expired-issuer',
      'ordinary-executor',
      'current-trust',
      'custodian-credential',
    ].includes(failure);
    // The host transaction rolls back source failures after the signed provisional
    // row opens exact installation-only reads. Pre-authentication failures write nothing.
    const writes = f.query.mock.calls.filter(([sql]) => /^(insert|update|delete)/iu.test(sql));
    expect(writes).toHaveLength(sourceFailure ? 1 : 0);
    if (sourceFailure)
      expect(writes[0]![0]).toContain('insert into control.identity_envelope_recovery_enrollment');
  });
  it('does not admit QA trust under production configuration', async () => {
    const f = fixture();
    await expect(
      installIdentityEnvelopeRecoveryReceivingTrust(f.client, f.trust, { localQaEnabled: false }),
    ).rejects.toThrow();
    expect(f.query.mock.calls.some(([sql]) => sql.startsWith('insert'))).toBe(false);
  });
  it('requires exact immutable signed readback after insertion', async () => {
    const f = fixture();
    f.facts.enrollmentState = 'REVOKED';
    await expect(
      enrollIdentityEnvelopeRecovery(f.client, f.signed, { localQaEnabled: true }),
    ).rejects.toThrow();
    // Caller transaction must roll back this provisional INSERT; no external I/O.
    expect(f.query.mock.calls.filter(([sql]) => sql.startsWith('insert'))).toHaveLength(1);
  });
  it('reports the precise failing owner phase and SQLSTATE without raw exceptions or custody input', async () => {
    const f = fixture();
    const error = Object.assign(new Error('private connection and key detail'), { code: '42501' });
    f.query.mockRejectedValueOnce(error);
    await expect(
      enrollIdentityEnvelopeRecovery(f.client, f.signed, { localQaEnabled: true }),
    ).rejects.toBe(error);
    expect(writeRecoveryDiagnostic).toHaveBeenCalledWith({
      boundary: 'identity_envelope_recovery_installation',
      command: 'ENROLL_SIGNER_REPAIR_CUSTODY',
      stage: 'ACCOUNT',
      outcome: 'REJECTED',
      sqlState: '42501',
      errorCode: 'SOURCE_UNAVAILABLE',
    });
    expect(JSON.stringify(vi.mocked(writeRecoveryDiagnostic).mock.calls)).not.toContain(
      error.message,
    );
    expect(JSON.stringify(vi.mocked(writeRecoveryDiagnostic).mock.calls)).not.toContain(
      f.signed.signature,
    );
  });
});
