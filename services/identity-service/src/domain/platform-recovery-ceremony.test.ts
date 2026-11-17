import { expect, it } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformRecoveryFixture } from './platform-recovery.test-fixture.js';
import {
  assertPlatformRecoveryCeremony,
  platformRecoveryProofMaxAgeMs,
  type PlatformRecoveryProof,
} from './platform-recovery-ceremony.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';

function fixture() {
  const { source, intent } = platformRecoveryFixture();
  const proofs: PlatformRecoveryProof[] = [
    source.enrollment.recoveryPrincipal,
    ...source.enrollment.custodians,
  ].map((v, i) => ({
    ...v,
    proofId: id(500 + i),
    sessionId: id(600 + i),
    sessionEpoch: '1',
    phase: i === 0 ? 'REQUEST' : 'APPROVE',
    intentDigest: canonicalAuthorizationDigest(intent),
    verifiedAt: source.now,
  }));
  return { source, intent, proofs };
}
it('preserves each original proof age when a QA case admits newly issued longer proofs', () => {
  const { source, intent, proofs } = fixture();
  const qaIntent = {
    ...intent,
    lifetimes: {
      profile: 'LOCAL_QA_10X' as const,
      leaseMs: 9_000_000,
      administratorMs: 36_000_000,
    },
    validUntil: new Date(source.now.getTime() + 3_600_000).toISOString(),
  };
  const pinned = proofs.map((proof) => ({
    ...proof,
    intentDigest: canonicalAuthorizationDigest(qaIntent),
    verifiedProofMaxAgeMs: 3000000 as const,
  }));
  const check = (selected: readonly PlatformRecoveryProof[], ageMs: number) =>
    assertPlatformRecoveryCeremony(
      source.enrollment,
      qaIntent,
      'REQUESTED',
      selected,
      'ACTIVATE',
      source.enrollment.recoveryPrincipal.principalId,
      new Date(source.now.getTime() + ageMs),
    );
  expect(() => check(pinned, 360_000)).not.toThrow();
  expect(() => check(pinned, 2_999_999)).not.toThrow();
  expect(() => check(pinned, 3_000_000)).toThrow();
  const legacy = pinned.map(({ verifiedProofMaxAgeMs: _pin, ...proof }) => proof);
  expect(() => check(legacy, 299_999)).not.toThrow();
  expect(() => check(legacy, 300_000)).toThrow();
  expect(() => check([pinned[0]!, legacy[1]!, pinned[2]!], 360_000)).toThrow();
  expect(() => platformRecoveryProofMaxAgeMs(pinned[0]!, intent)).toThrow();
  expect(() =>
    platformRecoveryProofMaxAgeMs(
      { ...pinned[0]!, verifiedProofMaxAgeMs: 600000 as never },
      qaIntent,
    ),
  ).toThrow();
});
it('requires a request and both fixed custodians before the executor may activate', () => {
  const { source, intent, proofs } = fixture();
  const enrollment = source.enrollment;
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      intent,
      'DRAFT',
      [],
      'REQUEST',
      enrollment.recoveryPrincipal.principalId,
      source.now,
    ),
  ).not.toThrow();
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      intent,
      'REQUESTED',
      proofs.slice(0, 1),
      'APPROVE',
      enrollment.custodians[0].principalId,
      source.now,
    ),
  ).not.toThrow();
  expect(() =>
    assertPlatformRecoveryCeremony(
      enrollment,
      intent,
      'REQUESTED',
      proofs,
      'ACTIVATE',
      enrollment.recoveryPrincipal.principalId,
      source.now,
    ),
  ).not.toThrow();
});
it.each([
  [
    'missing request',
    (v: ReturnType<typeof fixture>) => {
      v.proofs.shift();
    },
  ],
  [
    'missing custodian',
    (v: ReturnType<typeof fixture>) => {
      v.proofs.pop();
    },
  ],
  [
    'duplicate custodian',
    (v: ReturnType<typeof fixture>) => {
      v.proofs[2] = v.proofs[1]!;
    },
  ],
  [
    'wrong credential',
    (v: ReturnType<typeof fixture>) => {
      v.proofs[1] = { ...v.proofs[1]!, credentialId: id(999) };
    },
  ],
  [
    'changed credential epoch',
    (v: ReturnType<typeof fixture>) => {
      v.proofs[1] = { ...v.proofs[1]!, credentialEpoch: '1' };
    },
  ],
  [
    'changed principal epoch',
    (v: ReturnType<typeof fixture>) => {
      v.proofs[1] = { ...v.proofs[1]!, principalEpoch: '2' };
    },
  ],
  [
    'different intent',
    (v: ReturnType<typeof fixture>) => {
      v.intent.preparation.reason = 'different reviewed intent';
    },
  ],
  [
    'future proof',
    (v: ReturnType<typeof fixture>) => {
      v.proofs[1] = { ...v.proofs[1]!, verifiedAt: new Date(v.source.now.getTime() + 1) };
    },
  ],
  [
    'stale proof',
    (v: ReturnType<typeof fixture>) => {
      v.source.now = new Date(v.source.now.getTime() + 300000);
    },
  ],
  [
    'expired lease',
    (v: ReturnType<typeof fixture>) => {
      v.source.now = new Date(v.intent.validUntil);
    },
  ],
])('denies activation with %s', (_label, mutate) => {
  const v = fixture();
  mutate(v);
  expect(() =>
    assertPlatformRecoveryCeremony(
      v.source.enrollment,
      v.intent,
      'REQUESTED',
      v.proofs,
      'ACTIVATE',
      v.source.enrollment.recoveryPrincipal.principalId,
      v.source.now,
    ),
  ).toThrow();
});
it('does not let a subject or ordinary custodian request or activate recovery', () => {
  const { source, intent, proofs } = fixture();
  for (const principalId of [
    ...source.enrollment.administratorPrincipalIds,
    ...source.enrollment.custodians.map((v) => v.principalId),
  ]) {
    expect(() =>
      assertPlatformRecoveryCeremony(
        source.enrollment,
        intent,
        'DRAFT',
        [],
        'REQUEST',
        principalId,
        source.now,
      ),
    ).toThrow();
    expect(() =>
      assertPlatformRecoveryCeremony(
        source.enrollment,
        intent,
        'REQUESTED',
        proofs,
        'ACTIVATE',
        principalId,
        source.now,
      ),
    ).toThrow();
  }
});
it('does not duplicate a custodian approval or reopen an active ceremony', () => {
  const { source, intent, proofs } = fixture();
  expect(() =>
    assertPlatformRecoveryCeremony(
      source.enrollment,
      intent,
      'REQUESTED',
      proofs,
      'APPROVE',
      source.enrollment.custodians[0].principalId,
      source.now,
    ),
  ).toThrow();
  expect(() =>
    assertPlatformRecoveryCeremony(
      source.enrollment,
      intent,
      'ACTIVE',
      proofs,
      'ACTIVATE',
      source.enrollment.recoveryPrincipal.principalId,
      source.now,
    ),
  ).toThrow();
});
