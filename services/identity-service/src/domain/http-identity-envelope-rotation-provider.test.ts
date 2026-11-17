import { generateKeyPairSync } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import { createHttpIdentityEnvelopeRotationProvider } from './http-identity-envelope-rotation-provider.js';
import {
  identityEnvelopeRotationRequestDigest,
  type IdentityEnvelopeRotationRequest,
} from './identity-envelope-rotation-provider.js';

const transport = vi.hoisted(() => ({ exchange: vi.fn(), close: vi.fn() }));
vi.mock('./pinned-signing-transport.js', () => ({
  createPinnedSigningTransport: vi.fn(() => transport),
}));
const request: Extract<IdentityEnvelopeRotationRequest, { method: 'PREPARE' }> = {
  participantId: '01990000-0000-7000-8000-000000000001',
  privacyDomainId: '01990000-0000-7000-8000-000000000002',
  environmentId: 'disposable-qa',
  workloadCredentialId: '01990000-0000-7000-8000-000000000003',
  workloadCredentialEpoch: '1',
  callerWorkloadCredentialId: '01990000-0000-7000-8000-000000000004',
  rotationId: '01990000-0000-7000-8000-000000000005',
  operationId: '01990000-0000-7000-8000-000000000006',
  attemptId: '01990000-0000-7000-8000-000000000007',
  issuerParticipantEpoch: '7',
  issuerPrincipalEpoch: '1',
  governanceDigest: 'sha256:' + '71'.repeat(32),
  secretClass: 'SECRET-SIGNING-KEY',
  reference: 'secret://local/envelope-issuer#2',
  version: '2',
  purpose: identityEnvelopeContext.purpose,
  purposeCode: 371,
  schemaId: 24034,
  schemaVersion: 1,
  schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
  profileId: identityEnvelopeSigningProfile.profileId,
  profileVersion: 1,
  profileDigest: identityEnvelopeSigningProfileDigest,
  method: 'PREPARE',
};
const spki = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
  type: 'spki',
  format: 'der',
});
function observation() {
  const descriptor = {
    participantId: request.participantId,
    privacyDomainId: request.privacyDomainId,
    environmentId: request.environmentId,
    workloadCredentialId: request.workloadCredentialId,
    workloadCredentialEpoch: request.workloadCredentialEpoch,
    secretClass: request.secretClass,
    reference: request.reference,
    version: request.version,
    purpose: request.purpose,
    purposeCode: request.purposeCode,
    schemaId: request.schemaId,
    schemaVersion: request.schemaVersion,
    schemaDefinitionDigest: request.schemaDefinitionDigest,
    profileId: request.profileId,
    profileVersion: request.profileVersion,
    profileDigest: request.profileDigest,
    algorithm: 'ES256',
    fingerprint: evidenceKeyId(spki),
    publicKeySpkiHex: spki.toString('hex'),
    validFromNs: '1000',
    validUntilNs: '900000',
    state: 'ACTIVE',
    revokedAtNs: null,
    retiredAtNs: null,
  };
  return {
    schemaVersion: 1,
    providerId: 'local-envelope-provider',
    method: request.method,
    operationId: request.operationId,
    attemptId: request.attemptId,
    requestDigest: identityEnvelopeRotationRequestDigest(request),
    recordedAtNs: '2000',
    outcome: 'SUCCEEDED',
    reason: null,
    resultHex: null,
    descriptor,
  };
}
const provider = () =>
  createHttpIdentityEnvelopeRotationProvider({
    providerOrigin: 'https://provider.invalid',
    providerTlsSpkiDigest: 'sha256:' + '81'.repeat(32),
    callerWorkloadKeyDigest: 'sha256:' + '82'.repeat(32),
    certificate: Buffer.from('mocked'),
    privateKey: Buffer.from('mocked'),
    trustCa: Buffer.from('mocked'),
  });
beforeEach(() => {
  vi.clearAllMocks();
  transport.exchange.mockReset();
});
describe('purpose 371 rotation over mocked pinned transport', () => {
  it('uses the purpose-specific lifecycle path and exact request once', async () => {
    const expected = observation();
    transport.exchange.mockResolvedValue(expected);
    await expect(provider().perform(request)).resolves.toEqual(expected);
    expect(transport.exchange).toHaveBeenCalledExactlyOnceWith(
      '/v1/identity-envelope-signing/rotation/perform',
      request,
    );
  });
  it('rejects invalid purpose before any provider I/O', async () => {
    await expect(
      provider().perform({
        ...request,
        purposeCode: 338,
      } as unknown as IdentityEnvelopeRotationRequest),
    ).rejects.toThrow('reconciliation');
    expect(transport.exchange).not.toHaveBeenCalled();
  });
  it('preserves uncertain PREPARE without retrying its provider write', async () => {
    transport.exchange.mockRejectedValue(new Error('mocked response loss'));
    await expect(provider().perform(request)).rejects.toThrow('reconciliation');
    expect(transport.exchange).toHaveBeenCalledTimes(1);
  });
  it('rejects secret-bearing response fields without retaining or exposing the body', async () => {
    transport.exchange.mockResolvedValue({ ...observation(), privateKey: 'must-never-escape' });
    await expect(provider().perform(request)).rejects.toThrow('original-attempt reconciliation');
    expect(transport.exchange).toHaveBeenCalledTimes(1);
  });
  it('returns scoped NOT_FOUND as reconciliation information without performing a fresh write', async () => {
    const result = {
      state: 'NOT_FOUND',
      operationId: request.operationId,
      attemptId: request.attemptId,
      requestDigest: identityEnvelopeRotationRequestDigest(request),
    };
    transport.exchange.mockResolvedValue(result);
    await expect(provider().lookup(request)).resolves.toEqual(result);
    expect(transport.exchange).toHaveBeenCalledExactlyOnceWith(
      '/v1/identity-envelope-signing/rotation/lookup',
      request,
    );
  });
  it('rejects a lookup scoped to another operation', async () => {
    transport.exchange.mockResolvedValue({
      state: 'UNKNOWN',
      operationId: request.attemptId,
      attemptId: request.attemptId,
      requestDigest: identityEnvelopeRotationRequestDigest(request),
    });
    await expect(provider().lookup(request)).rejects.toThrow('reconciliation');
    expect(transport.exchange).toHaveBeenCalledTimes(1);
  });
  it('closes its transport explicitly', () => {
    provider().close();
    expect(transport.close).toHaveBeenCalledTimes(1);
  });
});
