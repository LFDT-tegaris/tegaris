import { createHash } from 'node:crypto';
import {
  transitionStatePreimage,
  type CborValue,
} from '@openpc/security-kernel/business-transition/state';
import { describe, expect, it } from 'vitest';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import type { NotificationEndpointBinding } from './endpoint-binding.js';
import {
  assertNotificationEndpointCreate,
  assertNotificationEndpointReplacement,
  assertNotificationEndpointVerificationState,
  assertNotificationEndpointVerification,
  bindNotificationEndpointBusinessState,
  parseNotificationEndpointBusinessState,
  type NotificationEndpointBusinessState,
} from './endpoint-business-state.js';

// Pure state contracts, not resolver/authority, SQL, signer or transport acceptance.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const digest = (byte: string) => `sha256:${byte.repeat(32)}`;
const scope = { participantId: id(1), privacyDomainId: id(2), aggregateId: id(3) };
const context = {
  ...scope,
  aggregateType: 'notification-endpoint',
  profileDigest: Buffer.alloc(32, 7), // Test-only binding input; no admitted profile is asserted.
};
const binding: NotificationEndpointBinding = {
  participantId: id(1),
  privacyDomainId: id(2),
  endpointId: id(3),
  revision: '1',
  channel: 'WEBHOOK',
  destinationRef: ref(4),
  channelProfileDigest: digest('ab'),
  credentialRef: ref(5),
};
const created: NotificationEndpointBusinessState = {
  ...binding,
  state: 'DISABLED',
  arbitraryEgress: false,
  candidateDigest: digest('cd'),
  verificationId: null,
};
const active: NotificationEndpointBusinessState = {
  ...created,
  state: 'ACTIVE',
  revision: '2',
  verificationId: id(6),
};
const verification = { ...binding, revision: '2', verificationId: id(6) };
const replacementBinding = {
  ...binding,
  revision: '3',
  channel: 'EMAIL' as const,
  destinationRef: ref(7),
  channelProfileDigest: digest('ef'),
  credentialRef: ref(8),
};
const replacement: NotificationEndpointBusinessState = {
  ...created,
  ...replacementBinding,
  candidateDigest: digest('12'),
};
const replaceInput = {
  expectedRevision: '2',
  replacementDigest: replacement.candidateDigest,
  binding: replacementBinding,
};
function rejects(operation: () => unknown) {
  expect(operation).toThrow(ConfigurationRepositoryError);
  expect(operation).toThrow('PC-DATA-6007');
}

describe('notification endpoint state projection', () => {
  it('uses explicit absence and the closed typed projection in the existing state domain', () => {
    const absent = bindNotificationEndpointBusinessState(context, undefined);
    expect(absent.reference).toMatchObject({ existence: 0, revision: 0n });
    expect(absent.preimage).toEqual(transitionStatePreimage(context, 0, 0n, new Map()));
    const projection = new Map<number, CborValue>([
      [0, 'WEBHOOK'],
      [1, 'DISABLED'],
      [2, ref(4)],
      [3, Buffer.alloc(32, 0xab)],
      [4, ref(5)],
      [5, 0n],
      [6, Buffer.alloc(32, 0xcd)],
      [7, 0n],
    ]);
    const present = bindNotificationEndpointBusinessState(context, created);
    expect(present.preimage).toEqual(transitionStatePreimage(context, 1, 1n, projection));
    expect(present.reference.stateDigest).toEqual(
      createHash('sha256').update(present.preimage).digest(),
    );
    expect(present.reference.stateDigest).not.toEqual(absent.reference.stateDigest);
    projection.set(1, 'ACTIVE');
    projection.set(7, 1n);
    projection.set(8, id(6));
    expect(bindNotificationEndpointBusinessState(context, active).preimage).toEqual(
      transitionStatePreimage(context, 1, 2n, projection),
    );
  });

  it('binds every endpoint field, exact reference namespace and verification identity', () => {
    const original = bindNotificationEndpointBusinessState(context, active).reference.stateDigest;
    for (const change of [
      { channel: 'EMAIL' },
      { destinationRef: ref(9) },
      { destinationRef: `urn:openpc:participant:${id(4)}` },
      { channelProfileDigest: digest('01') },
      { credentialRef: ref(9) },
      { candidateDigest: digest('02') },
      { verificationId: id(9) },
      { revision: '3' },
      { state: 'DISABLED', verificationId: null },
      { state: 'QUARANTINED', verificationId: null },
      { state: 'RETIRED', verificationId: null },
    ])
      expect(
        bindNotificationEndpointBusinessState(context, { ...active, ...change }).reference
          .stateDigest,
      ).not.toEqual(original);
    expect(
      bindNotificationEndpointBusinessState(
        { ...context, profileDigest: Buffer.alloc(32, 8) },
        active,
      ).reference.stateDigest,
    ).not.toEqual(original);
  });

  it('rejects foreign scope, aggregate namespaces and malformed profile inputs even for absence', () => {
    for (const key of ['participantId', 'privacyDomainId', 'aggregateId'] as const) {
      rejects(() => bindNotificationEndpointBusinessState({ ...context, [key]: id(9) }, active));
      rejects(() =>
        bindNotificationEndpointBusinessState({ ...context, [key]: `${id(9)}\n` }, undefined),
      );
      const field = key === 'aggregateId' ? 'endpointId' : key;
      const digestBefore = bindNotificationEndpointBusinessState(context, active).reference
        .stateDigest;
      expect(
        bindNotificationEndpointBusinessState(
          { ...context, [key]: id(9) },
          { ...active, [field]: id(9) },
        ).reference.stateDigest,
      ).not.toEqual(digestBefore);
    }
    for (const aggregateType of ['notification', 'work-item', 'notification-endpoint\n'])
      rejects(() =>
        bindNotificationEndpointBusinessState({ ...context, aggregateType }, undefined),
      );
    for (const profileDigest of [Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33)])
      rejects(() =>
        bindNotificationEndpointBusinessState({ ...context, profileDigest }, undefined),
      );
  });

  it('returns an immutable closed read shape without treating it as authority', () => {
    const row = { ...created };
    const parsed = parseNotificationEndpointBusinessState(scope, row);
    expect(parsed).toEqual(created);
    expect(Object.isFrozen(parsed)).toBe(true);
    row.destinationRef = ref(9);
    expect(parsed?.destinationRef).toBe(ref(4));
    expect(parseNotificationEndpointBusinessState(scope, undefined)).toBeUndefined();
    for (const value of [
      null,
      [],
      { ...created, verified: true },
      { ...created, secret: 'PRIVATE_MARKER' },
    ])
      rejects(() => parseNotificationEndpointBusinessState(scope, value));
    try {
      parseNotificationEndpointBusinessState(scope, {
        ...created,
        credentialRef: 'PRIVATE_MARKER',
      });
    } catch (error) {
      expect(String(error)).not.toContain('PRIVATE_MARKER');
    }
  });

  it.each(['0', '01', '-1', '1.0', 'invalid', '1\n', '18446744073709551616'])(
    'rejects noncanonical or overflowing revision %j with the owning safe error',
    (revision) => {
      rejects(() => bindNotificationEndpointBusinessState(context, { ...created, revision }));
    },
  );

  it('preserves full u64 precision and rejects malformed digests, identities and impossible states', () => {
    expect(
      bindNotificationEndpointBusinessState(context, {
        ...created,
        revision: '18446744073709551615',
      }).reference.revision,
    ).toBe(18446744073709551615n);
    for (const change of [
      { candidateDigest: digest('AB') },
      { channelProfileDigest: `${digest('ab')}\n` },
      { candidateDigest: 'sha256:00' },
      { endpointId: `${id(3)}\n` },
      { destinationRef: `${ref(4)}\n` },
      { credentialRef: `${ref(5)} ` },
      { verificationId: `${id(6)}\n`, state: 'ACTIVE', revision: '2' },
      { arbitraryEgress: true },
      { channel: 'SMTP' },
      { state: 'VERIFIED' },
      { state: 'ACTIVE', verificationId: id(6) },
      { state: 'ACTIVE', revision: '2' },
      { verificationId: id(6) },
      { state: 'QUARANTINED' },
      { state: 'RETIRED' },
    ])
      rejects(() => bindNotificationEndpointBusinessState(context, { ...created, ...change }));
  });
});

describe('endpoint transition consistency, without admission or activation', () => {
  it('creates only an absent, disabled revision-one endpoint matching the supplied candidate', () => {
    const input = { binding, candidateDigest: created.candidateDigest };
    assertNotificationEndpointCreate(scope, undefined, created, input);
    for (const after of [
      undefined,
      active,
      { ...created, revision: '2' },
      { ...created, candidateDigest: digest('ab') },
    ])
      rejects(() => assertNotificationEndpointCreate(scope, undefined, after, input));
    rejects(() => assertNotificationEndpointCreate(scope, created, created, input));
    for (const change of [
      { participantId: id(9) },
      { privacyDomainId: id(9) },
      { endpointId: id(9) },
      { channel: 'EMAIL' as const },
      { destinationRef: ref(9) },
      { channelProfileDigest: digest('ef') },
      { credentialRef: ref(9) },
      { revision: '2' },
    ])
      rejects(() =>
        assertNotificationEndpointCreate(scope, undefined, created, {
          ...input,
          binding: { ...binding, ...change },
        }),
      );
  });

  it('clears verification on exact next-revision replacement and preserves quarantine', () => {
    assertNotificationEndpointReplacement(scope, active, replacement, replaceInput);
    for (const state of ['DISABLED', 'QUARANTINED'] as const)
      assertNotificationEndpointReplacement(
        scope,
        { ...active, state, verificationId: null },
        { ...replacement, state },
        replaceInput,
      );
    rejects(() =>
      assertNotificationEndpointReplacement(
        scope,
        { ...active, state: 'QUARANTINED', verificationId: null },
        replacement,
        replaceInput,
      ),
    );
    rejects(() =>
      assertNotificationEndpointReplacement(
        scope,
        { ...active, state: 'RETIRED', verificationId: null },
        replacement,
        replaceInput,
      ),
    );
    // Even identical routing needs a fresh verification after candidate/revision replacement.
    const sameRouting = { ...binding, revision: '3' };
    assertNotificationEndpointReplacement(
      scope,
      active,
      { ...replacement, ...sameRouting },
      { ...replaceInput, binding: sameRouting },
    );
  });

  it('rejects stale/no-op, absent, skipped-revision and unbound replacements', () => {
    for (const before of [undefined, created])
      rejects(() =>
        assertNotificationEndpointReplacement(scope, before, replacement, replaceInput),
      );
    for (const after of [
      undefined,
      { ...replacement, state: 'ACTIVE', verificationId: id(6) },
      { ...replacement, candidateDigest: created.candidateDigest },
      { ...replacement, destinationRef: ref(9) },
      { ...replacement, credentialRef: ref(9) },
      { ...replacement, channelProfileDigest: digest('34') },
      { ...replacement, participantId: id(9) },
    ])
      rejects(() => assertNotificationEndpointReplacement(scope, active, after, replaceInput));
    for (const revision of ['2', '4'])
      rejects(() =>
        assertNotificationEndpointReplacement(
          scope,
          active,
          { ...replacement, revision },
          { ...replaceInput, binding: { ...replacementBinding, revision } },
        ),
      );
    for (const expectedRevision of ['1', '02', 'invalid', '18446744073709551616'])
      rejects(() =>
        assertNotificationEndpointReplacement(scope, active, replacement, {
          ...replaceInput,
          expectedRevision,
        }),
      );
    rejects(() =>
      assertNotificationEndpointReplacement(
        scope,
        active,
        { ...replacement, candidateDigest: active.candidateDigest },
        { ...replaceInput, replacementDigest: active.candidateDigest },
      ),
    );
  });

  it('cannot wrap the maximum revision or lose integer precision on replacement', () => {
    const revision = '9007199254740994';
    assertNotificationEndpointReplacement(
      scope,
      { ...active, revision: '9007199254740993' },
      { ...replacement, revision },
      {
        ...replaceInput,
        expectedRevision: '9007199254740993',
        binding: { ...replacementBinding, revision },
      },
    );
    rejects(() =>
      assertNotificationEndpointReplacement(
        scope,
        { ...active, revision: '18446744073709551615' },
        created,
        { ...replaceInput, expectedRevision: '18446744073709551615', binding },
      ),
    );
  });

  it('requires the retained verification identity and every exact binding field, without activating', () => {
    assertNotificationEndpointVerificationState(scope, active, verification);
    for (const change of [
      { participantId: id(9) },
      { privacyDomainId: id(9) },
      { endpointId: id(9) },
      { revision: '1' },
      { revision: '3' },
      { channel: 'EMAIL' as const },
      { destinationRef: ref(9) },
      { channelProfileDigest: digest('34') },
      { credentialRef: ref(9) },
      { verificationId: id(9) },
    ])
      rejects(() =>
        assertNotificationEndpointVerificationState(scope, active, { ...verification, ...change }),
      );
    for (const state of ['DISABLED', 'QUARANTINED', 'RETIRED'] as const)
      rejects(() =>
        assertNotificationEndpointVerificationState(
          scope,
          { ...active, state, verificationId: null },
          verification,
        ),
      );
    rejects(() => assertNotificationEndpointVerificationState(scope, undefined, verification));
    expect(created.state).toBe('DISABLED');
    expect(created.verificationId).toBeNull();
  });
});

describe('authenticated verification transition consistency', () => {
  const input = { expectedRevision: '1', verification };
  it('advances the exact disabled predecessor and retains its original candidate digest', () => {
    assertNotificationEndpointVerification(scope, created, active, input);
    const renewed = { ...active, revision: '3', verificationId: id(9) };
    assertNotificationEndpointVerification(scope, active, renewed, {
      expectedRevision: '2',
      verification: { ...verification, revision: '3', verificationId: id(9) },
    });
    // Neither consistency assertion mutates its input or creates verification authority.
    expect(created.state).toBe('DISABLED');
  });
  it('rejects a lost predecessor, stale revision, quarantine, retirement and identity reuse', () => {
    for (const before of [
      undefined,
      { ...created, revision: '2' },
      { ...active, state: 'QUARANTINED', verificationId: null },
      { ...active, state: 'RETIRED', verificationId: null },
    ])
      rejects(() => assertNotificationEndpointVerification(scope, before, active, input));
    for (const after of [
      undefined,
      created,
      { ...active, revision: '3' },
      { ...active, candidateDigest: digest('ef') },
      { ...active, destinationRef: ref(9) },
      { ...active, credentialRef: ref(9) },
      { ...active, channelProfileDigest: digest('ef') },
      { ...active, channel: 'EMAIL' },
      { ...active, privacyDomainId: id(9) },
    ])
      rejects(() => assertNotificationEndpointVerification(scope, created, after, input));
    rejects(() =>
      assertNotificationEndpointVerification(
        scope,
        active,
        { ...active, revision: '3' },
        {
          expectedRevision: '2',
          verification: { ...verification, revision: '3' },
        },
      ),
    );
    rejects(() =>
      assertNotificationEndpointVerification(scope, created, active, {
        ...input,
        verification: { ...verification, verificationId: id(9) },
      }),
    );
  });
  it('retains full revision precision and rejects overflow on verification', () => {
    const before = { ...active, revision: '9007199254740993' };
    const after = { ...active, revision: '9007199254740994', verificationId: id(9) };
    assertNotificationEndpointVerification(scope, before, after, {
      expectedRevision: before.revision,
      verification: { ...verification, revision: after.revision, verificationId: id(9) },
    });
    rejects(() =>
      assertNotificationEndpointVerification(
        scope,
        { ...before, revision: '18446744073709551615' },
        { ...after, revision: '18446744073709551616' },
        {
          expectedRevision: '18446744073709551615',
          verification: { ...verification, revision: '18446744073709551616' },
        },
      ),
    );
  });
});
