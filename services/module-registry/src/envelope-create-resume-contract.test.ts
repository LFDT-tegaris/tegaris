import { expect, it } from 'vitest';
import {
  envelopeFixtureId,
  envelopeFixtureScope,
} from '../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { isEnvelopeCreateResumeCandidate } from './envelope-create-resume-contract.js';
const now = 1_800_000_000_000;
function fixture() {
  const scope = envelopeFixtureScope();
  scope.validFromNs = String(BigInt(now - 1000) * 1_000_000n);
  scope.validUntilNs = String(BigInt(now + 1000) * 1_000_000n);
  const resourceId = envelopeFixtureId(60),
    participantId = envelopeFixtureId(1);
  return {
    catalogOperationId: 'ID-OP-ENVELOPE-CREATE',
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    resourceType: 'participant',
    operationClass: 'UPDATE',
    expectedRevision: '0',
    resourceId,
    participantId,
    document: {
      schema: 'pc.identity.authority-envelope-proposal',
      schemaVersion: 1,
      envelopeId: resourceId,
      id: resourceId,
      participantId,
      state: 'DRAFT',
      issuance: 'PLATFORM_ROOT',
      usable: scope,
      grantable: scope,
    },
  };
}
it('permits an unchanged bounded same-Participant root request before its original deadline', () => {
  expect(isEnvelopeCreateResumeCandidate(fixture(), now)).toBe(true);
});
it.each([
  'catalogOperationId',
  'actionIntentId',
  'resourceType',
  'operationClass',
  'expectedRevision',
  'resourceId',
  'participantId',
] as const)('rejects a changed %s owning binding', (key) => {
  expect(isEnvelopeCreateResumeCandidate({ ...fixture(), [key]: 'foreign' }, now)).toBe(false);
});
it.each(['usable', 'grantable'] as const)(
  'denies at and after the original %s deadline with exact integer arithmetic',
  (dimension) => {
    const value = fixture();
    for (const offset of [-1000n, 0n, 1000n]) {
      value.document = {
        ...value.document,
        [dimension]: {
          ...value.document[dimension],
          validUntilNs: String(BigInt(now) * 1_000_000n + offset),
        },
      };
      expect(isEnvelopeCreateResumeCandidate(value, now)).toBe(offset > 0n);
    }
  },
);
it.each([
  { issuance: 'CHILD' },
  { platformScopeReplacementId: envelopeFixtureId(30) },
  { participantId: envelopeFixtureId(2) },
  { envelopeId: envelopeFixtureId(61) },
  { state: 'ACTIVE' },
  { schemaVersion: 2 },
  { extra: 'unsigned' },
])('rejects unsupported or changed body %j', (change) => {
  const value = fixture();
  expect(
    isEnvelopeCreateResumeCandidate({ ...value, document: { ...value.document, ...change } }, now),
  ).toBe(false);
});
