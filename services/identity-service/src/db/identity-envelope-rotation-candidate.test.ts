import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  signingRotationActions,
  type EnvelopeSigningRotationRequest,
} from '../domain/signing-rotation.js';
import type { IdentityEnvelopeRotationIssuer } from './identity-envelope-rotation-issuer.js';
import {
  captureIdentityEnvelopeRotationCandidate,
  captureIdentityEnvelopeRotationSource,
} from './identity-envelope-rotation-candidate.js';
import { assertWorkloadCredentialContinuation } from './workload-credential-continuation.js';
vi.mock('./workload-credential-continuation.js', () => ({
  assertWorkloadCredentialContinuation: vi.fn(),
}));

const capture = vi.hoisted(() => vi.fn());
vi.mock('./identity-envelope-rotation-issuer.js', async (original) => ({
  ...(await original<typeof import('./identity-envelope-rotation-issuer.js')>()),
  captureIdentityEnvelopeRotationIssuer: capture,
}));
const id = (n: number) => `01990000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const key = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
  type: 'spki',
  format: 'der',
});
const trust: IdentityEnvelopeSigningTrust = {
  participantId: id(1),
  privacyDomainId: id(2),
  environmentId: 'retained-qa',
  signerId: evidenceKeyId(key),
  publicKeySpkiDer: key,
  workloadCredentialId: id(3),
  workloadCredentialEpoch: 1n,
  workloadParticipantEpoch: 1n,
  workloadPrincipalEpoch: 1n,
  keyEpoch: 1n,
  validFromNs: 1000n,
  validUntilNs: 900000n,
  admissionKind: 'BOOTSTRAP',
  admissionReference: 'initial-test-trust',
  admissionDigest: Buffer.alloc(32, 1),
  secretClass: 'SECRET-SIGNING-KEY',
  secretReference: 'secret://local/envelope-issuer#1',
  secretVersion: '1',
  purpose: identityEnvelopeContext.purpose,
  profileId: 'pc.identity.authority-envelope.v1',
  profileVersion: 1,
  profileDigest: identityEnvelopeSigningProfileDigest,
};
const issuer: IdentityEnvelopeRotationIssuer = {
  participantId: id(1),
  privacyDomainId: id(2),
  workloadCredentialId: id(3),
  workloadPrincipalId: id(4),
  workloadParticipantEpoch: '7',
  workloadPrincipalEpoch: '1',
  workloadCredentialEpoch: '1',
  workloadPublicKeyDigest: 'sha256:' + '71'.repeat(32),
  credentialValidFromNs: '1000',
  credentialValidUntilNs: '900000',
};
const request: EnvelopeSigningRotationRequest = {
  actionIntentId: signingRotationActions.create,
  actionIntentDigest: 'sha256:' + '72'.repeat(32),
  secretClass: 'SECRET-SIGNING-KEY',
  signerRole: 'IDENTITY_ENVELOPE',
  purpose: trust.purpose,
  environmentId: trust.environmentId,
  workloadCredentialId: id(3),
  oldReference: trust.secretReference,
  oldFingerprint: trust.signerId,
  newReference: 'secret://local/envelope-issuer#2',
  reason: 'Repair stale epoch binding',
};
const scope = { participantId: id(1), privacyDomainId: id(2), principalId: id(5) };
function source() {
  return {
    participant_id: trust.participantId,
    privacy_domain_id: trust.privacyDomainId,
    signer_id: trust.signerId,
    environment_id: trust.environmentId,
    public_key_spki_der: key,
    workload_credential_id: trust.workloadCredentialId,
    workload_credential_epoch: '1',
    key_epoch: '1',
    envelope_workload_participant_epoch: '1',
    envelope_workload_principal_epoch: '1',
    valid_from_ns: '1000',
    valid_until_ns: '900000',
    admission_kind: 'BOOTSTRAP',
    admission_reference: trust.admissionReference,
    admission_digest: trust.admissionDigest,
    secret_class: trust.secretClass,
    secret_reference: trust.secretReference,
    secret_version: '1',
    trust_preimage: identityEnvelopeSigningTrustPreimage(trust),
    trust_digest: Buffer.from(identityEnvelopeSigningTrustDigest(trust).slice(7), 'hex'),
    admission_version: '1',
    now_ns: '3000',
  };
}
function client(row: Record<string, unknown> | null = source(), prior?: unknown) {
  const query = vi.fn(async (sql: string) => {
    if (sql.includes('identity_envelope_signing_selection'))
      return { rowCount: row ? 1 : 0, rows: row ? [row] : [] };
    if (sql.includes('mutation_candidate'))
      return { rowCount: prior ? 1 : 0, rows: prior ? [prior] : [] };
    throw new Error('Unexpected SQL; no mutation is allowed in capture');
  });
  return { query, value: { query } as unknown as PoolClient };
}
beforeEach(() => {
  vi.mocked(assertWorkloadCredentialContinuation).mockReset();
  capture.mockReset();
  capture.mockResolvedValue({ issuer, recordedAtNs: 3000n });
});
describe('server-captured envelope rotation candidate provenance', () => {
  it('requires authenticated immediate continuation for a changed issuer credential', async () => {
    const renewed = { ...issuer, workloadCredentialId: id(90), workloadCredentialEpoch: '2' };
    capture.mockResolvedValue({ issuer: renewed, recordedAtNs: 3000n });
    const c = client();
    const verifier = { verifyCanonicalAssertion: vi.fn() };
    const result = await captureIdentityEnvelopeRotationSource(
      c.value,
      scope,
      { ...request, workloadCredentialId: renewed.workloadCredentialId },
      verifier,
    );
    expect(result.trust.workloadCredentialId).toBe(trust.workloadCredentialId);
    expect(assertWorkloadCredentialContinuation).toHaveBeenCalledWith(
      c.value,
      {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        principalId: renewed.workloadPrincipalId,
        predecessorId: trust.workloadCredentialId,
        predecessorEpoch: '1',
        successorId: renewed.workloadCredentialId,
        successorEpoch: '2',
      },
      verifier,
    );
    vi.mocked(assertWorkloadCredentialContinuation).mockRejectedValue(new Error('Unavailable'));
    await expect(
      captureIdentityEnvelopeRotationSource(
        c.value,
        scope,
        { ...request, workloadCredentialId: renewed.workloadCredentialId },
        verifier,
      ),
    ).rejects.toThrow('Unavailable');
  });
  it('binds current epoch7 while preserving original epoch1 trust and never writes', async () => {
    const c = client();
    const before = identityEnvelopeSigningTrustPreimage(trust);
    const result = await captureIdentityEnvelopeRotationCandidate(
      c.value,
      scope,
      request,
      id(6),
      'original-intent',
    );
    expect(result.candidate.issuerSnapshot.workloadParticipantEpoch).toBe('7');
    expect(result.candidate.oldTrustDigest).toBe(identityEnvelopeSigningTrustDigest(trust));
    expect(result.candidate.selectionAdmissionVersion).toBe('1');
    expect(result.candidate.creationOperationId).toBe(id(6));
    expect(identityEnvelopeSigningTrustPreimage(trust)).toEqual(before);
    expect(c.query.mock.calls.every(([sql]) => !/\b(insert|update|delete)\b/iu.test(sql))).toBe(
      true,
    );
  });
  it('retains the original creation operation on exact proposal replay', async () => {
    const first = await captureIdentityEnvelopeRotationCandidate(
      client().value,
      scope,
      request,
      id(6),
      'original-intent',
    );
    const prior = {
      rotationId: id(8),
      candidate: first.candidate,
      digest: Buffer.from(canonicalAuthorizationDigest(first.candidate).slice(7), 'hex'),
    };
    const replay = await captureIdentityEnvelopeRotationCandidate(
      client(source(), prior).value,
      scope,
      request,
      id(7),
      'original-intent',
    );
    expect(replay.candidate).toEqual(first.candidate);
  });
  it('does not refresh original epochs during historical replay', async () => {
    const first = await captureIdentityEnvelopeRotationCandidate(
      client().value,
      scope,
      request,
      id(6),
      'original-intent',
    );
    capture.mockResolvedValue({
      issuer: { ...issuer, workloadParticipantEpoch: '8' },
      recordedAtNs: 3000n,
    });
    const prior = {
      rotationId: id(8),
      candidate: first.candidate,
      digest: Buffer.from(canonicalAuthorizationDigest(first.candidate).slice(7), 'hex'),
    };
    capture.mockClear();
    const replay = await captureIdentityEnvelopeRotationCandidate(
      client(null, prior).value,
      scope,
      request,
      id(7),
      'original-intent',
    );
    expect(replay.candidate.issuerSnapshot.workloadParticipantEpoch).toBe('7');
    expect(replay.replayRotationId).toBe(id(8));
    expect(capture).not.toHaveBeenCalled();
  });
  it.each([
    { trust_digest: Buffer.alloc(32, 9) },
    { trust_preimage: Buffer.from('forged') },
    { environment_id: 'foreign' },
    { workload_credential_epoch: '2' },
    { admission_version: '0' },
  ])('rejects substituted source metadata: %j', async (change) => {
    await expect(
      captureIdentityEnvelopeRotationCandidate(
        client({ ...source(), ...change }).value,
        scope,
        request,
        id(6),
        'original-intent',
      ),
    ).rejects.toThrow();
  });
  it('rejects absent selected active source', async () => {
    await expect(
      captureIdentityEnvelopeRotationCandidate(
        client(null).value,
        scope,
        request,
        id(6),
        'original-intent',
      ),
    ).rejects.toThrow();
  });
  it('does not read the key if current issuer capture is unavailable', async () => {
    capture.mockRejectedValue(new Error('issuer unavailable'));
    const c = client();
    await expect(
      captureIdentityEnvelopeRotationCandidate(c.value, scope, request, id(6), 'original-intent'),
    ).rejects.toThrow();
    expect(
      c.query.mock.calls.every(([sql]) => !sql.includes('identity_envelope_signing_selection')),
    ).toBe(true);
  });
  it.each(['digest', 'request', 'foreign'] as const)(
    'rejects substituted historical %s',
    async (field) => {
      const first = await captureIdentityEnvelopeRotationCandidate(
        client().value,
        scope,
        request,
        id(6),
        'original-intent',
      );
      const candidate = structuredClone(first.candidate);
      if (field === 'request') candidate.request.reason = 'Different business intent';
      if (field === 'foreign') candidate.issuerSnapshot.participantId = id(9);
      const prior = {
        rotationId: id(8),
        candidate,
        digest:
          field === 'digest'
            ? Buffer.alloc(32, 9)
            : Buffer.from(canonicalAuthorizationDigest(candidate).slice(7), 'hex'),
      };
      await expect(
        captureIdentityEnvelopeRotationCandidate(
          client(null, prior).value,
          scope,
          request,
          id(7),
          'original-intent',
        ),
      ).rejects.toThrow();
    },
  );
});
