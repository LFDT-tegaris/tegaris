import { describe, expect, it } from 'vitest';
import { decodeCbor, encodeCbor } from '../canonical-cbor.js';
import { decodeEnvelopeScope, encodeEnvelopeScope } from './codec.js';
import { envelopeFixtureId, envelopeFixtureDigest, envelopeFixtureScope } from './fixture.js';
import { identityEnvelopeContext } from './generated.js';
import {
  platformEnvelopeScopeDigest,
  platformEnvelopeScopePreimage,
  type PlatformEnvelopeScopeAdmission,
} from './platform-scope.js';

const input = (): PlatformEnvelopeScopeAdmission => ({
  platformContextId: envelopeFixtureId(4),
  ownerParticipantId: envelopeFixtureId(1),
  installationPrivacyDomainId: envelopeFixtureId(2),
  platformAuthorityEpoch: '1',
  environmentId: 'platform-test',
  installationDigest: envelopeFixtureDigest(1),
  grantable: envelopeFixtureScope(),
});
describe('initial Platform typed upper bound', () => {
  it('binds every installation identity and exact frozen Scope bytes in a separate domain', () => {
    const value = input(),
      bytes = platformEnvelopeScopePreimage(value);
    expect(decodeCbor(bytes)).toEqual([
      'pc.identity.platform-envelope-scope.v1',
      24034n,
      1n,
      Buffer.from(identityEnvelopeContext.definitionDigest.slice(7), 'hex'),
      Buffer.from(value.platformContextId.replaceAll('-', ''), 'hex'),
      Buffer.from(value.ownerParticipantId.replaceAll('-', ''), 'hex'),
      Buffer.from(value.installationPrivacyDomainId.replaceAll('-', ''), 'hex'),
      1n,
      'platform-test',
      Buffer.from(value.installationDigest.slice(7), 'hex'),
      encodeEnvelopeScope(value.grantable),
    ]);
    expect(decodeEnvelopeScope(encodeEnvelopeScope(value.grantable))).toEqual(value.grantable);
    for (const change of [
      { platformContextId: envelopeFixtureId(5) },
      { ownerParticipantId: envelopeFixtureId(5) },
      { installationPrivacyDomainId: envelopeFixtureId(5) },
      { platformAuthorityEpoch: '2' },
      { environmentId: 'another-test' },
      { installationDigest: envelopeFixtureDigest(2) },
      { grantable: { ...value.grantable, onwardDelegationDepth: 1 } },
    ])
      expect(platformEnvelopeScopeDigest({ ...value, ...change })).not.toBe(
        platformEnvelopeScopeDigest(value),
      );
  });
  it('rejects implicit, extra, malformed or executable installation authority', () => {
    for (const change of [
      { extra: true },
      { platformAuthorityEpoch: '0' },
      { platformAuthorityEpoch: '01' },
      { platformAuthorityEpoch: '18446744073709551616' },
      { environmentId: '*' },
      { installationDigest: 'a'.repeat(64) },
      { ownerParticipantId: envelopeFixtureId(1).replace('-7000-', '-4000-') },
      { installationPrivacyDomainId: undefined },
    ])
      expect(() =>
        platformEnvelopeScopePreimage({ ...input(), ...change } as PlatformEnvelopeScopeAdmission),
      ).toThrow();
    const value = input();
    Object.defineProperty(value, 'grantable', {
      get: () => {
        throw new Error('getter executed');
      },
    });
    expect(() => platformEnvelopeScopePreimage(value)).toThrow(
      'Platform envelope scope unavailable',
    );
  });
  it('keeps finite sorted dimensions and exact canonical decode fail closed', () => {
    const value = input().grantable;
    for (const administration of [
      { ...value.administration, resourceIds: ['*'] },
      { ...value.administration, participantIds: [envelopeFixtureId(1), envelopeFixtureId(1)] },
      { ...value.administration, dataClasses: ['B', 'A'] },
      { ...value.administration, actionIntentIds: ['READ'] },
      { ...value.administration, extra: [] },
    ])
      expect(() => encodeEnvelopeScope({ ...value, administration })).toThrow();
    for (const change of [
      { validUntilNs: value.validFromNs },
      { validFromNs: '1' },
      { onwardDelegationDepth: 33 },
    ])
      expect(() => encodeEnvelopeScope({ ...value, ...change })).toThrow();
    expect(() =>
      decodeEnvelopeScope(Buffer.concat([encodeEnvelopeScope(value), Buffer.from([0])])),
    ).toThrow();
    expect(() => decodeEnvelopeScope(encodeCbor(new Map()))).toThrow();
    const empty = {
      ...value,
      administration: {
        participantIds: [],
        privacyDomainIds: [],
        resourceIds: [],
        dataClasses: [],
        targetProfileIds: [],
        riskClasses: [],
        actionIntentIds: [],
      },
    };
    expect(decodeEnvelopeScope(encodeEnvelopeScope(empty))).toEqual(empty);
  });
});
