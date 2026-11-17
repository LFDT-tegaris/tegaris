import { describe, expect, it } from 'vitest';
import { decodeCbor } from '../canonical-cbor.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from './fixture.js';
import { platformEnvelopeScopePreimage } from './platform-scope.js';
import {
  platformEnvelopeScopeExpiryRecoveryDigest,
  platformEnvelopeScopeExpiryRecoveryPreimage,
  type PlatformEnvelopeScopeExpiryRecovery,
} from './platform-scope-expiry-recovery.js';

const input = (): PlatformEnvelopeScopeExpiryRecovery => ({
  admission: {
    platformContextId: id(4),
    ownerParticipantId: id(1),
    installationPrivacyDomainId: id(2),
    platformAuthorityEpoch: '2',
    environmentId: 'platform-test',
    installationDigest: digest(1),
    grantable: envelopeFixtureScope(),
  },
  recoveryId: id(10),
  activationOperationId: id(11),
  enrollmentDigest: digest(4),
  intentDigest: digest(5),
  predecessorEpoch: '1',
  predecessorDigest: digest(2),
});

describe('independent local Root expiry successor', () => {
  it('separates installation and replacement, binding the exact predecessor and preparation', () => {
    const value = input();
    expect(decodeCbor(platformEnvelopeScopeExpiryRecoveryPreimage(value))).toEqual([
      'pc.identity.platform-envelope-scope.local-expiry-recovery.v1',
      1n,
      Buffer.from(id(10).replaceAll('-', ''), 'hex'),
      Buffer.from(id(11).replaceAll('-', ''), 'hex'),
      Buffer.from(digest(4).slice(7), 'hex'),
      Buffer.from(digest(5).slice(7), 'hex'),
      1n,
      Buffer.from(digest(2).slice(7), 'hex'),
      platformEnvelopeScopePreimage(value.admission),
    ]);
    for (const change of [
      { recoveryId: id(12) },
      { activationOperationId: id(13) },
      { predecessorDigest: digest(3) },
      { enrollmentDigest: digest(6) },
      { intentDigest: digest(7) },
      {
        admission: {
          ...value.admission,
          grantable: { ...value.admission.grantable, stepUpRequired: false },
        },
      },
    ])
      expect(platformEnvelopeScopeExpiryRecoveryDigest({ ...value, ...change })).not.toBe(
        platformEnvelopeScopeExpiryRecoveryDigest(value),
      );
  });
  it('rejects skipped, overflowing or noncanonical epochs and unbound identities', () => {
    for (const change of [
      { predecessorEpoch: '0' },
      { predecessorEpoch: '01' },
      { predecessorEpoch: '18446744073709551615' },
      { predecessorEpoch: '2' },
      { recoveryId: id(10).replace('-7000-', '-4000-') },
      { predecessorDigest: '0'.repeat(64) },
      { extra: true },
    ])
      expect(() =>
        platformEnvelopeScopeExpiryRecoveryPreimage({
          ...input(),
          ...change,
        } as PlatformEnvelopeScopeExpiryRecovery),
      ).toThrow();
    const value = input();
    Object.defineProperty(value.admission, 'grantable', {
      get() {
        throw new Error('getter executed');
      },
    });
    expect(() => platformEnvelopeScopeExpiryRecoveryPreimage(value)).toThrow(
      'Platform envelope scope unavailable',
    );
  });
});
