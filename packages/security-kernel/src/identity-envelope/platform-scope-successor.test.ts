import { describe, expect, it } from 'vitest';
import { decodeCbor } from '../canonical-cbor.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from './fixture.js';
import { platformEnvelopeScopePreimage } from './platform-scope.js';
import {
  platformEnvelopeScopeSuccessorDigest,
  platformEnvelopeScopeSuccessorPreimage,
  type PlatformEnvelopeScopeSuccessor,
} from './platform-scope-successor.js';

const input = (): PlatformEnvelopeScopeSuccessor => ({
  admission: {
    platformContextId: id(4),
    ownerParticipantId: id(1),
    installationPrivacyDomainId: id(2),
    platformAuthorityEpoch: '2',
    environmentId: 'platform-test',
    installationDigest: digest(1),
    grantable: envelopeFixtureScope(),
  },
  replacementId: id(10),
  preparationOperationId: id(11),
  predecessorEpoch: '1',
  predecessorDigest: digest(2),
});

describe('governed Platform successor source', () => {
  it('separates installation and replacement, binding the exact predecessor and preparation', () => {
    const value = input();
    expect(decodeCbor(platformEnvelopeScopeSuccessorPreimage(value))).toEqual([
      'pc.identity.platform-envelope-scope.successor.v1',
      1n,
      Buffer.from(id(10).replaceAll('-', ''), 'hex'),
      Buffer.from(id(11).replaceAll('-', ''), 'hex'),
      1n,
      Buffer.from(digest(2).slice(7), 'hex'),
      platformEnvelopeScopePreimage(value.admission),
    ]);
    for (const change of [
      { replacementId: id(12) },
      { preparationOperationId: id(13) },
      { predecessorDigest: digest(3) },
      {
        admission: {
          ...value.admission,
          grantable: { ...value.admission.grantable, stepUpRequired: false },
        },
      },
    ])
      expect(platformEnvelopeScopeSuccessorDigest({ ...value, ...change })).not.toBe(
        platformEnvelopeScopeSuccessorDigest(value),
      );
  });
  it('rejects skipped, overflowing or noncanonical epochs and unbound identities', () => {
    for (const change of [
      { predecessorEpoch: '0' },
      { predecessorEpoch: '01' },
      { predecessorEpoch: '18446744073709551615' },
      { predecessorEpoch: '2' },
      { replacementId: id(10).replace('-7000-', '-4000-') },
      { predecessorDigest: '0'.repeat(64) },
      { extra: true },
    ])
      expect(() =>
        platformEnvelopeScopeSuccessorPreimage({
          ...input(),
          ...change,
        } as PlatformEnvelopeScopeSuccessor),
      ).toThrow();
    const value = input();
    Object.defineProperty(value.admission, 'grantable', {
      get() {
        throw new Error('getter executed');
      },
    });
    expect(() => platformEnvelopeScopeSuccessorPreimage(value)).toThrow(
      'Platform envelope scope unavailable',
    );
  });
});
