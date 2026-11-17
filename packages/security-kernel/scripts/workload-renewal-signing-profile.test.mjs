import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { workloadRenewalSigningProfileRegistration } from './workload-renewal-signing-profile.mjs';
const profile = () =>
  JSON.parse(
    readFileSync(
      new URL(
        '../../../schemas/canonical/workload-renewal-signing-profiles/policy-authorization-v2.json',
        import.meta.url,
      ),
      'utf8',
    ),
  );
it('admits exact unsigned v2 trust metadata while keeping signed24039/376/v1 immutable', () => {
  expect(workloadRenewalSigningProfileRegistration(profile()).profile).toMatchObject({
    profileVersion: 2,
    schemaId: 24039,
    purposeCode: 376,
    signedArtifactProfileVersion: 1,
    authorizationMode: 'POLICY_AUTHORIZED',
  });
});
it.each([
  'profileVersion',
  'schemaId',
  'schemaVersion',
  'schemaDefinitionDigest',
  'purpose',
  'purposeCode',
  'authorizationMode',
  'actionIntentId',
  'catalogOperationId',
  'signedArtifactProfileVersion',
  'trustDomain',
  'trustFields',
  'securityOwners',
  'currentUse',
  'consumerAdmission',
])('rejects substituted %s metadata instead of granting another role', (field) => {
  expect(() =>
    workloadRenewalSigningProfileRegistration({ ...profile(), [field]: 'changed' }),
  ).toThrow();
});
it('rejects unknown fields and reordered canonical trust fields', () => {
  expect(() =>
    workloadRenewalSigningProfileRegistration({ ...profile(), approved: true }),
  ).toThrow();
  const reordered = profile();
  reordered.trustFields.reverse();
  expect(() => workloadRenewalSigningProfileRegistration(reordered)).toThrow();
});
