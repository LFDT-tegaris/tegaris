import { sign } from 'node:crypto';
import { expect, it } from 'vitest';
import { identityEnvelopeSigningTrustDigest } from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../../identity-service/src/contracts/authorization.js';
import { planIdentityEnvelopeRotationAttempts } from '../../identity-service/src/domain/identity-envelope-rotation-plan.js';
import { recoveryFixtureId as id } from '../../identity-service/src/domain/identity-envelope-recovery.test-fixture.js';
import {
  identityEnvelopeRotationPossessionPreimage,
  identityEnvelopeRotationRequestDigest,
} from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';
import { authenticateIdentityEnvelopeRotationDualProof } from './identity-envelope-rotation-proof.js';
import { identityEnvelopeDualProofFixture as fixture } from './identity-envelope-rotation-proof.test-fixture.js';

it('authenticates both keys while retaining the original credential binding through continued-credential recovery', () => {
  const f = fixture({ expiredPredecessor: true, continuedCredential: true });
  const old = f.records[0]!;
  expect(old.request.workloadCredentialId).toBe(f.input.currentIssuer.workloadCredentialId);
  expect(old.observation.descriptor.workloadCredentialId).toBe(
    f.input.oldTrust.workloadCredentialId,
  );
  const result = f.authenticate();
  expect(result.trust.workloadCredentialId).toBe(f.input.currentIssuer.workloadCredentialId);
  expect(result.trust.workloadCredentialEpoch).toBe(2n);
  old.observation.descriptor.workloadCredentialId = f.input.currentIssuer.workloadCredentialId;
  old.firstObservation.descriptor = { ...old.observation.descriptor };
  expect(() => f.authenticate()).toThrow('dual possession proof unavailable');
});

it('admits a fresh independently leased predecessor possession proof without renewing expired old trust', () => {
  const f = fixture({ expiredPredecessor: true });
  const old = f.records[0]!;
  const next = f.records[1]!;
  expect(f.input.oldTrust.validUntilNs).toBeLessThan(f.input.nowNs);
  const binding = old.request.recoveryPredecessor;
  if (!('kind' in f.input.admission)) throw Error('Recovery fixture required');
  expect(binding?.leaseDigest).toBe(canonicalAuthorizationDigest(f.input.admission.lease));
  expect(binding?.oldTrustDigest).toBe(identityEnvelopeSigningTrustDigest(f.input.oldTrust));
  expect(next.request.recoveryPredecessor).toBeUndefined();
  const result = f.authenticate();
  expect(result.trust.validUntilNs).toBeGreaterThan(f.input.nowNs);
  expect(result.proofExpiresAtNs - BigInt(old.request.challengeIssuedAtNs)).toBeLessThanOrEqual(
    300000000000n,
  );
  expect(old.observation.descriptor.validUntilNs).toBe(f.input.oldTrust.validUntilNs.toString());
});

it.each(['lease', 'activation', 'missing', 'new-slot'] as const)(
  'rejects independently signed predecessor recovery binding drift: %s',
  (kind) => {
    const f = fixture({ expiredPredecessor: true });
    const old = f.records[0]!;
    if (!old.request.recoveryPredecessor) throw Error('Explicit predecessor binding required');
    const record = kind === 'new-slot' ? f.records[1]! : old;
    record.request = {
      ...record.request,
      recoveryPredecessor:
        kind === 'missing'
          ? undefined
          : {
              ...old.request.recoveryPredecessor,
              ...(kind === 'lease' ? { leaseDigest: 'sha256:' + '99'.repeat(32) } : {}),
              ...(kind === 'activation' ? { activationOperationId: id(999) } : {}),
            },
    };
    if (kind === 'missing') delete record.request.recoveryPredecessor;
    record.observation = {
      ...record.observation,
      requestDigest: identityEnvelopeRotationRequestDigest(record.request),
      resultHex: sign('sha256', identityEnvelopeRotationPossessionPreimage(record.request), {
        key: record.slot === 'old' ? f.oldKey.privateKey : f.newKey.privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('hex'),
    };
    record.firstObservation = { ...record.observation };
    expect(f.authenticate).toThrow('dual possession proof unavailable');
  },
);

it('keeps expired predecessor signing validity binding for an ordinary approved rotation', () => {
  const f = fixture({ expiredPredecessor: true });
  const admission = {
    rotationId: f.input.rotationId,
    operationId: id(800),
    candidateDigest: 'sha256:' + '81'.repeat(32),
    approvalRequestId: id(801),
    approvalDecisionDigest: 'sha256:' + '82'.repeat(32),
    makerPrincipalId: id(802),
    checkerPrincipalId: id(803),
    oldTrustDigest: identityEnvelopeSigningTrustDigest(f.input.oldTrust),
  };
  expect(() =>
    planIdentityEnvelopeRotationAttempts({ ...f.input, admission }, () => id(804)),
  ).toThrow();
});

it('authenticates two real independent ES256 signatures bound to the exact original requests and successor trust', () => {
  const f = fixture();
  const result = f.authenticate();
  expect(result.trustDigest).toBe(identityEnvelopeSigningTrustDigest(f.trust));
  expect(result.trust.workloadParticipantEpoch).toBe(7n);
  expect(result.trust.workloadPrincipalEpoch).toBe(2n);
  expect(result.observationsDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
  expect(result.proofExpiresAtNs).toBeGreaterThan(f.input.nowNs);
  expect(result).not.toHaveProperty('consumerAccepted');
  expect(result).not.toHaveProperty('authority');
  expect(authenticateIdentityEnvelopeRotationDualProof(f.input, [...f.records].reverse())).toEqual(
    result,
  );
});

it.each([
  'missing',
  'duplicate-slot',
  'extra-slot',
  'wrong-slot',
  'duplicate-attempt',
  'foreign-scope',
  'wrong-operation',
  'wrong-challenge',
  'wrong-key',
  'changed-first',
  'missing-first',
  'future-observation',
  'expired-proof',
  'expired-lease',
  'issuer-drift',
  'changed-descriptor',
  'old-validity',
  'different-issue-time',
] as const)('rejects dual possession %s without producing admission evidence', (kind) => {
  const f = fixture();
  const old = f.records[0]!;
  const next = f.records[1]!;
  if (kind === 'missing') f.records.pop();
  if (kind === 'duplicate-slot') next.slot = old.slot;
  if (kind === 'extra-slot') f.records.push({ ...next, slot: 'effective' });
  if (kind === 'wrong-slot') next.slot = 'effective';
  if (kind === 'duplicate-attempt')
    next.request = { ...next.request, attemptId: old.request.attemptId };
  if (kind === 'foreign-scope') next.request = { ...next.request, privacyDomainId: id(900) };
  if (kind === 'wrong-operation') next.request = { ...next.request, operationId: id(901) };
  if (kind === 'wrong-challenge') next.request = { ...next.request, challengeHex: '99'.repeat(32) };
  if (kind === 'different-issue-time')
    next.request = {
      ...next.request,
      challengeIssuedAtNs: (BigInt(next.request.challengeIssuedAtNs) + 1000n).toString(),
    };
  if (kind === 'wrong-key')
    next.observation.resultHex = sign(
      'sha256',
      identityEnvelopeRotationPossessionPreimage(next.request),
      {
        key: f.oldKey.privateKey,
        dsaEncoding: 'ieee-p1363',
      },
    ).toString('hex');
  if (kind === 'changed-first')
    next.firstObservation = {
      ...next.firstObservation,
      recordedAtNs: (BigInt(next.firstObservation.recordedAtNs) + 1000n).toString(),
    };
  if (kind === 'missing-first') next.firstObservation = null as never;
  if (kind === 'future-observation') {
    next.observation.recordedAtNs = (f.input.nowNs + 1000n).toString();
    next.firstObservation = { ...next.observation };
  }
  if (kind === 'expired-proof') f.input.nowNs = BigInt(next.request.challengeExpiresAtNs);
  if (kind === 'expired-lease') f.input.nowNs = f.input.authorityValidUntilNs;
  if (kind === 'issuer-drift')
    f.input.currentIssuer = { ...f.input.currentIssuer, workloadPrincipalEpoch: '3' };
  if (kind === 'changed-descriptor')
    f.input.descriptor = {
      ...f.input.descriptor!,
      validUntilNs: (BigInt(f.input.descriptor!.validUntilNs) - 1000n).toString(),
    };
  if (kind === 'old-validity') {
    old.observation.descriptor = {
      ...old.observation.descriptor,
      validUntilNs: (BigInt(old.observation.descriptor.validUntilNs) - 1000n).toString(),
    };
    old.firstObservation = { ...old.observation };
  }
  expect(f.authenticate).toThrow('dual possession proof unavailable');
});

it('rejects a live but shortened and independently signed challenge that differs from the immutable planned window', () => {
  const f = fixture();
  for (const record of f.records) {
    record.request = {
      ...record.request,
      challengeExpiresAtNs: (BigInt(record.request.challengeExpiresAtNs) - 1000n).toString(),
    };
    record.observation = {
      ...record.observation,
      requestDigest: identityEnvelopeRotationRequestDigest(record.request),
      resultHex: sign('sha256', identityEnvelopeRotationPossessionPreimage(record.request), {
        key: record.slot === 'old' ? f.oldKey.privateKey : f.newKey.privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('hex'),
    };
    record.firstObservation = { ...record.observation };
  }
  expect(f.authenticate).toThrow('dual possession proof unavailable');
});
