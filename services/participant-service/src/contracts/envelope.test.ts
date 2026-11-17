import { describe, expect, it } from 'vitest';
import {
  envelopeFixtureId as id,
  envelopeFixtureScope,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { envelopeCreate, typedEnvelopeCreateCandidate } from './envelope.js';

const request = () => ({
  schema: 'pc.identity.authority-envelope-proposal',
  schemaVersion: 1,
  envelopeId: id(1),
  issuance: 'CHILD',
  usable: envelopeFixtureScope(),
  grantable: envelopeFixtureScope(),
});
describe('versioned envelope create input', () => {
  it('accepts desired typed slices and the existing legacy body as distinct contracts', () => {
    expect(envelopeCreate.parse(request())).toEqual(request());
    const legacy = {
      envelopeId: id(1),
      semanticDigest: `sha256:${'1'.repeat(64)}`,
      privacyDomainIds: [id(2)],
      actionIntentIds: [],
      resourceIds: [id(3)],
      riskClasses: ['HIGH'],
      validFrom: '2027-01-01T00:00:00Z',
      validUntil: '2027-01-02T00:00:00Z',
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
    };
    expect(envelopeCreate.parse(legacy).envelopeId).toBe(id(1));
    expect(envelopeCreate.safeParse({ ...request(), ...legacy }).success).toBe(false);
  });
  it('denies unknown versions/dimensions, wildcard, omitted grantable and caller-fabricated authority', () => {
    for (const changes of [
      { schemaVersion: 2 },
      { envelopeId: '018f0000-0000-4000-8000-000000000001' },
      { schema: 'other' },
      { issuance: 'ROTATION' },
      { authorityEpoch: '1' },
      { parentEnvelopeId: id(5) },
      { semanticDigest: `sha256:${'1'.repeat(64)}` },
      { signer: {} },
      { issuer: {} },
      { approvalRequestId: id(6) },
    ])
      expect(envelopeCreate.safeParse({ ...request(), ...changes }).success).toBe(false);
    const missing: Record<string, unknown> = request();
    delete missing.grantable;
    expect(envelopeCreate.safeParse(missing).success).toBe(false);
    const wildcard = request();
    wildcard.usable.administration.resourceIds = ['*'];
    expect(envelopeCreate.safeParse(wildcard).success).toBe(false);
    const dimension = request();
    Reflect.deleteProperty(dimension.usable.runtime, 'targetProfileIds');
    expect(envelopeCreate.safeParse(dimension).success).toBe(false);
  });
  it('rejects unsorted/duplicate scope, unbounded/nonexact time and changed candidate identity', () => {
    const duplicate = request();
    duplicate.grantable.runtime.dataClasses = ['a', 'a'];
    expect(envelopeCreate.safeParse(duplicate).success).toBe(false);
    const nanos = request();
    nanos.usable.validUntilNs = '18446744073709551616';
    expect(envelopeCreate.safeParse(nanos).success).toBe(false);
    const nullTime = request();
    Reflect.set(nullTime.usable, 'validUntilNs', null);
    expect(envelopeCreate.safeParse(nullTime).success).toBe(false);
    const candidate = { ...request(), id: id(1), participantId: id(1), state: 'DRAFT' };
    expect(typedEnvelopeCreateCandidate.safeParse(candidate).success).toBe(true);
    expect(typedEnvelopeCreateCandidate.safeParse({ ...candidate, id: id(99) }).success).toBe(
      false,
    );
  });
});
