import { generateKeyPairSync } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import {
  identityEnvelopeRotationRequestDigest,
  type IdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationRequest,
} from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';
import {
  IdentityEnvelopeRotationWorker,
  type ClaimedIdentityEnvelopeRotationAttempt,
} from './identity-envelope-rotation-worker.js';

const id = (n: number) => `01990000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
function fixture(mode: 'PERFORM' | 'LOOKUP' = 'PERFORM') {
  const publicKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  const binding = {
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'local',
    workloadCredentialId: id(3),
    workloadCredentialEpoch: '1',
    secretClass: 'SECRET-SIGNING-KEY' as const,
    reference: 'secret://local/envelope#2',
    version: '2',
    purpose: identityEnvelopeContext.purpose,
    purposeCode: 371 as const,
    schemaId: 24034 as const,
    schemaVersion: 1 as const,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: identityEnvelopeSigningProfile.profileId,
    profileVersion: 1 as const,
    profileDigest: identityEnvelopeSigningProfileDigest,
  } as const;
  const request: IdentityEnvelopeRotationRequest = {
    ...binding,
    callerWorkloadCredentialId: id(3),
    rotationId: id(4),
    operationId: id(5),
    attemptId: id(6),
    issuerParticipantEpoch: '7',
    issuerPrincipalEpoch: '2',
    governanceDigest: 'sha256:' + '71'.repeat(32),
    method: 'PREPARE',
  };
  const observation: IdentityEnvelopeRotationObservation = {
    schemaVersion: 1,
    providerId: 'local-provider',
    attemptId: request.attemptId,
    operationId: request.operationId,
    requestDigest: identityEnvelopeRotationRequestDigest(request),
    method: 'PREPARE',
    recordedAtNs: '100000',
    outcome: 'SUCCEEDED',
    reason: null,
    resultHex: null,
    descriptor: {
      ...binding,
      algorithm: 'ES256',
      publicKeySpkiHex: publicKey.toString('hex'),
      fingerprint: evidenceKeyId(publicKey),
      validFromNs: '1000',
      validUntilNs: '900000',
      state: 'ACTIVE',
      revokedAtNs: null,
      retiredAtNs: null,
    },
  };
  const claim: ClaimedIdentityEnvelopeRotationAttempt = { request, mode };
  const events: string[] = [];
  const store = {
    claimNext: vi.fn(async () => {
      events.push('committed-start');
      return claim;
    }),
    recordFirst: vi.fn(async () => {
      events.push('first');
    }),
    recordResolved: vi.fn(async () => {
      events.push('resolved');
    }),
    recordAmbiguous: vi.fn(async () => {
      events.push('ambiguous');
    }),
  };
  const provider = {
    perform: vi.fn(async () => {
      events.push('perform');
      return observation;
    }),
    lookup: vi.fn(async () => {
      events.push('lookup');
      return { state: 'OBSERVED' as const, observation };
    }),
    close: vi.fn(),
  };
  const worker = new IdentityEnvelopeRotationWorker(store, provider);
  return { request, observation, claim, events, store, provider, worker };
}
it('starts before provider I/O and durably preserves the first response before original-attempt confirmation', async () => {
  const f = fixture();
  expect(await f.worker.runOnce()).toBe(true);
  expect(f.events).toEqual(['committed-start', 'perform', 'first', 'lookup', 'resolved']);
  expect(f.provider.lookup).toHaveBeenCalledWith(f.request, f.observation);
  expect(f.store.recordResolved).toHaveBeenCalledWith(f.request, f.observation);
});
it.each([true, false])(
  'reconciles an already started attempt without a write (stored first response=%s)',
  async (hasFirst) => {
    const f = fixture('LOOKUP');
    if (hasFirst) Object.assign(f.claim, { firstObservation: f.observation });
    await f.worker.runOnce();
    expect(f.provider.perform).not.toHaveBeenCalled();
    expect(f.provider.lookup).toHaveBeenCalledWith(f.request, hasFirst ? f.observation : undefined);
    expect(f.store.recordResolved).toHaveBeenCalledOnce();
  },
);
it('recovers a lost provider response from the exact original lookup without another perform', async () => {
  const f = fixture();
  f.provider.perform.mockRejectedValueOnce(Error('response lost after possible effect'));
  await f.worker.runOnce();
  expect(f.events).toEqual(['committed-start', 'lookup', 'first', 'resolved']);
  expect(f.provider.perform).toHaveBeenCalledOnce();
});
it.each(['NOT_FOUND', 'UNKNOWN'] as const)(
  'preserves %s as ambiguity without replaying a started write',
  async (state) => {
    const f = fixture('LOOKUP');
    f.provider.lookup.mockResolvedValueOnce({
      state,
      attemptId: f.request.attemptId,
      operationId: f.request.operationId,
      requestDigest: identityEnvelopeRotationRequestDigest(f.request),
    } as never);
    await f.worker.runOnce();
    expect(f.store.recordAmbiguous).toHaveBeenCalledWith(f.request, state);
    expect(f.store.recordResolved).not.toHaveBeenCalled();
    expect(f.provider.perform).not.toHaveBeenCalled();
  },
);
it('rejects changed original observation while retaining the durable first response', async () => {
  const f = fixture();
  f.provider.lookup.mockResolvedValueOnce({
    state: 'OBSERVED',
    observation: { ...f.observation, recordedAtNs: '101000' },
  });
  await f.worker.runOnce();
  expect(f.store.recordFirst).toHaveBeenCalledWith(f.request, f.observation);
  expect(f.store.recordAmbiguous).toHaveBeenCalledWith(f.request, 'LOOKUP_UNAVAILABLE');
  expect(f.store.recordResolved).not.toHaveBeenCalled();
});
it.each(['first', 'resolved'])(
  'propagates %s persistence failure without another provider attempt',
  async (failure) => {
    const f = fixture();
    (failure === 'first' ? f.store.recordFirst : f.store.recordResolved).mockRejectedValueOnce(
      Error('database unavailable'),
    );
    await expect(f.worker.runOnce()).rejects.toThrow('database unavailable');
    expect(f.provider.perform).toHaveBeenCalledOnce();
    expect(f.store.recordAmbiguous).not.toHaveBeenCalled();
  },
);
it('rejects a cross-purpose stored request before contacting the provider', async () => {
  const f = fixture();
  Object.assign(f.request, { purposeCode: 338 });
  await expect(f.worker.runOnce()).rejects.toThrow();
  expect(f.provider.perform).not.toHaveBeenCalled();
  expect(f.provider.lookup).not.toHaveBeenCalled();
});
it('does nothing without a claimed original', async () => {
  const f = fixture();
  f.store.claimNext.mockResolvedValueOnce(undefined as never);
  expect(await f.worker.runOnce()).toBe(false);
  expect(f.provider.perform).not.toHaveBeenCalled();
  expect(f.provider.lookup).not.toHaveBeenCalled();
});
