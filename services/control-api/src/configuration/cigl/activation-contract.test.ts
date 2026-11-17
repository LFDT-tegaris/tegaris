import { expect, it } from 'vitest';
import { activateCiglProfilesSchema } from './activation-contract.js';

const ref = (suffix: string) => `urn:openpc:resource:019963de-8824-7000-8000-${suffix}`;
const digest = `sha256:${'ab'.repeat(32)}`;
const selection = {
  profileId: ref('000000000001'),
  profileRevision: '1',
  profileDigest: digest,
  compilationArtifactDigest: digest,
  grantSourcesDigest: digest,
};
const command = {
  actionIntentId: 'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',
  actionIntentDigest: digest,
  reason: 'Publish the reviewed profiles with their current source pins.',
  targetRef: ref('000000000003'),
  expectedRevision: '3',
  expectedGenerationDigest: digest,
  participantEpoch: '1',
  profiles: [selection, { ...selection, profileId: ref('000000000002') }],
};

it('requires an exact bounded and ordered profile selection for target activation', () => {
  expect(activateCiglProfilesSchema.safeParse(command).success).toBe(true);
  for (const profiles of [
    [],
    [...command.profiles].reverse(),
    [selection, selection],
    Array.from({ length: 65 }, (_, index) => ({
      ...selection,
      profileId: ref(String(index + 1).padStart(12, '0')),
    })),
  ])
    expect(activateCiglProfilesSchema.safeParse({ ...command, profiles }).success).toBe(false);
  for (const field of ['targetRef', 'expectedGenerationDigest', 'participantEpoch'])
    expect(activateCiglProfilesSchema.safeParse({ ...command, [field]: undefined }).success).toBe(
      false,
    );
  for (const field of Object.keys(selection))
    expect(
      activateCiglProfilesSchema.safeParse({
        ...command,
        profiles: [{ ...selection, [field]: undefined }],
      }).success,
    ).toBe(false);
});

it('does not accept caller artifacts, readiness, source grants or authority', () => {
  for (const field of [
    'replacementDigest',
    'ready',
    'active',
    'profileCbor',
    'signedReceipt',
    'grants',
    'verificationKey',
    'participantId',
  ]) {
    expect(activateCiglProfilesSchema.safeParse({ ...command, [field]: true }).success).toBe(false);
    expect(
      activateCiglProfilesSchema.safeParse({
        ...command,
        profiles: [{ ...selection, [field]: true }],
      }).success,
    ).toBe(false);
  }
  for (const change of [
    { participantEpoch: '0' },
    { participantEpoch: '01' },
    { participantEpoch: '9223372036854775808' },
    { expectedRevision: '0' },
    { targetRef: command.targetRef.replace(':resource:', ':workload:') },
    { expectedGenerationDigest: '0x1234' },
  ])
    expect(activateCiglProfilesSchema.safeParse({ ...command, ...change }).success).toBe(false);
  for (const change of [
    { profileRevision: '0' },
    { profileRevision: '01' },
    { profileRevision: '9223372036854775808' },
    { profileId: selection.profileId.replace(':resource:', ':workload:') },
    { grantSourcesDigest: '0x1234' },
  ])
    expect(
      activateCiglProfilesSchema.safeParse({ ...command, profiles: [{ ...selection, ...change }] })
        .success,
    ).toBe(false);
});

it('binds policy renewal to an exact occurrence revision and generation, without caller readiness', () => {
  const policyRenewal = {
    activationOccurrenceRef: ref('000000000004'),
    expectedRevision: '1',
    policyGenerationDigest: digest,
  };
  expect(activateCiglProfilesSchema.parse({ ...command, policyRenewal }).policyRenewal).toEqual(
    policyRenewal,
  );
  for (const change of [
    { activationOccurrenceRef: undefined },
    { expectedRevision: undefined },
    { policyGenerationDigest: undefined },
    { expectedRevision: '0' },
    { expectedRevision: '9223372036854775808' },
    { policyGenerationDigest: '0x1234' },
    { activationOccurrenceRef: command.targetRef.replace(':resource:', ':participant:') },
    { ready: true },
    { approved: true },
    { expiresAt: '2099-01-01T00:00:00Z' },
  ])
    expect(
      activateCiglProfilesSchema.safeParse({
        ...command,
        policyRenewal: { ...policyRenewal, ...change },
      }).success,
    ).toBe(false);
});
