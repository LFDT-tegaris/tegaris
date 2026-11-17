import { describe, expect, it } from 'vitest';
import {
  assertEndpointVerificationBinding,
  endpointStateAfterReplacement,
  notificationEndpointBinding,
  notificationEndpointState,
  notificationUserState,
  type NotificationEndpointBinding,
} from './endpoint-binding.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const binding: NotificationEndpointBinding = {
  participantId: id(1),
  privacyDomainId: id(2),
  endpointId: id(3),
  revision: '7',
  channel: 'WEBHOOK',
  destinationRef: `urn:openpc:resource:${id(4)}`,
  channelProfileDigest: `sha256:${'ab'.repeat(32)}`,
  credentialRef: `urn:openpc:resource:${id(5)}`,
};

describe('notification endpoint exact verification binding', () => {
  it('compares the retained exact binding without inventing an authority or verification result', () => {
    expect(assertEndpointVerificationBinding(binding, { ...binding })).toBeUndefined();
    expect(notificationEndpointState.options).toEqual([
      'ACTIVE',
      'DISABLED',
      'QUARANTINED',
      'RETIRED',
    ]);
    expect(notificationUserState.options).toEqual(['UNREAD', 'READ', 'ACKNOWLEDGED']);
    expect(notificationEndpointBinding.safeParse({ ...binding, verified: true }).success).toBe(
      false,
    );
  });

  it.each([
    { participantId: id(11) },
    { privacyDomainId: id(12) },
    { endpointId: id(13) },
    { revision: '8' },
    { channel: 'EMAIL' as const },
    { destinationRef: `urn:openpc:resource:${id(14)}` },
    { channelProfileDigest: `sha256:${'cd'.repeat(32)}` },
    { credentialRef: `urn:openpc:resource:${id(15)}` },
  ])('rejects a changed verification field: %j', (changed) => {
    expect(() => assertEndpointVerificationBinding(binding, { ...binding, ...changed })).toThrow();
    expect(() => assertEndpointVerificationBinding({ ...binding, ...changed }, binding)).toThrow();
  });

  it.each([
    { revision: '01' },
    { revision: '0' },
    { revision: '18446744073709551616' },
    { participantId: 'invalid' },
    { channel: 'SMTP' },
    { destinationRef: 'https://unapproved.example' },
    { credentialRef: 'smtp-password' },
    { channelProfileDigest: `sha256:${'AB'.repeat(32)}` },
    { ready: true },
  ])('rejects malformed binding fields: %j', (changed) => {
    expect(() =>
      assertEndpointVerificationBinding(
        { ...binding, ...changed } as NotificationEndpointBinding,
        binding,
      ),
    ).toThrow();
  });

  it('invalidates verification on revision-only and destination/profile/credential replacements', () => {
    for (const change of [
      {},
      { destinationRef: `urn:openpc:resource:${id(14)}` },
      { channelProfileDigest: `sha256:${'cd'.repeat(32)}` },
      { credentialRef: `urn:openpc:resource:${id(15)}` },
    ]) {
      const replacement = { ...binding, ...change, revision: '8' };
      expect(endpointStateAfterReplacement('ACTIVE', binding, replacement)).toBe('DISABLED');
      expect(endpointStateAfterReplacement('DISABLED', binding, replacement)).toBe('DISABLED');
      expect(() => assertEndpointVerificationBinding(replacement, binding)).toThrow();
    }
  });

  it('cannot lift quarantine or resurrect a retired endpoint through replacement', () => {
    const next = { ...binding, revision: '8' };
    expect(endpointStateAfterReplacement('QUARANTINED', binding, next)).toBe('QUARANTINED');
    expect(() => endpointStateAfterReplacement('RETIRED', binding, next)).toThrow();
  });

  it('rejects stale, skipped, cross-scope and overflow replacement revisions', () => {
    for (const change of [
      { revision: '7' },
      { revision: '9' },
      { participantId: id(11) },
      { privacyDomainId: id(12) },
      { endpointId: id(13) },
    ]) {
      expect(() =>
        endpointStateAfterReplacement('ACTIVE', binding, { ...binding, revision: '8', ...change }),
      ).toThrow();
    }
    const high = { ...binding, revision: '9007199254740993' };
    expect(
      endpointStateAfterReplacement('ACTIVE', high, { ...high, revision: '9007199254740994' }),
    ).toBe('DISABLED');
    const exhausted = { ...binding, revision: '18446744073709551615' };
    expect(() =>
      endpointStateAfterReplacement('ACTIVE', exhausted, {
        ...exhausted,
        revision: '18446744073709551616',
      }),
    ).toThrow();
  });
});
