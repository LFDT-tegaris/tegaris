import { expect, it } from 'vitest';
import { identityEnvelopeContext } from '@openpc/security-kernel';
import { businessSigningPurpose } from '../domain/business-signing-provider.js';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import { workloadSigningHandoverRequestSchema } from './workload-signing-handover.js';

const id = (value: number) => `01990000-0000-7000-8000-${String(value).padStart(12, '0')}`;
const hash = (value: number) => `sha256:${value.toString(16).padStart(64, '0')}`;
function request() {
  return {
    schemaVersion: 1,
    actionIntentId: signingRotationActions.create,
    actionIntentDigest: hash(1),
    environmentId: 'synthetic',
    predecessorCredentialId: id(1),
    successorCredentialId: id(2),
    credentialRotationOperationId: id(3),
    replacements: [
      {
        oldFingerprint: hash(2),
        oldTrustDigest: hash(3),
        expectedKeyEpoch: '1',
        oldReference: 'secret://synthetic/business#1',
        newReference: 'secret://synthetic/business-successor#1',
        signerRole: 'BUSINESS_EFFECT',
        purpose: businessSigningPurpose,
      },
      {
        oldFingerprint: hash(4),
        oldTrustDigest: hash(5),
        expectedKeyEpoch: '1',
        oldReference: 'secret://synthetic/lifecycle#1',
        newReference: 'secret://synthetic/lifecycle-successor#1',
        signerRole: 'LIFECYCLE_EVIDENCE',
        purpose: businessSigningPurpose,
      },
      {
        oldFingerprint: hash(6),
        oldTrustDigest: hash(7),
        expectedKeyEpoch: '1',
        oldReference: 'secret://synthetic/envelope#1',
        newReference: 'secret://synthetic/envelope-successor#1',
        signerRole: 'IDENTITY_ENVELOPE',
        purpose: identityEnvelopeContext.purpose,
      },
    ],
    reason: 'Replace keys for the natively rotated workload credential.',
  };
}

it('represents both typed signing purposes without claiming possession or admission', () => {
  const value = request();
  expect(workloadSigningHandoverRequestSchema.parse(value)).toEqual(value);
  expect(workloadSigningHandoverRequestSchema.parse(value)).not.toHaveProperty('state');
});

it.each(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE'])(
  'rejects assigning the envelope purpose to the %s receipt role',
  (signerRole) => {
    const value = request();
    value.replacements[2]!.signerRole = signerRole;
    expect(workloadSigningHandoverRequestSchema.safeParse(value).success).toBe(false);
  },
);

it('rejects assigning a receipt purpose to the envelope role', () => {
  const value = request();
  value.replacements[0]!.signerRole = 'IDENTITY_ENVELOPE';
  expect(workloadSigningHandoverRequestSchema.safeParse(value).success).toBe(false);
});

it.each(['participantId', 'privacyDomainId', 'principalId', 'current', 'approved', 'newTrust'])(
  'rejects caller-supplied %s as a substitute for owning scope or authority',
  (field) => {
    expect(
      workloadSigningHandoverRequestSchema.safeParse({ ...request(), [field]: id(9) }).success,
    ).toBe(false);
  },
);

it.each(['profileIds', 'grants', 'descriptor', 'possessionVerified', 'validUntilNs'])(
  'rejects caller-supplied replacement %s',
  (field) => {
    const value = request();
    const [first, ...rest] = value.replacements;
    expect(
      workloadSigningHandoverRequestSchema.safeParse({
        ...value,
        replacements: [{ ...first, [field]: 'caller-asserted' }, ...rest],
      }).success,
    ).toBe(false);
  },
);

it('rejects credential aliases and absent native rotation provenance', () => {
  const value = request();
  expect(
    workloadSigningHandoverRequestSchema.safeParse({
      ...value,
      successorCredentialId: value.predecessorCredentialId,
    }).success,
  ).toBe(false);
  expect(
    workloadSigningHandoverRequestSchema.safeParse({
      ...value,
      credentialRotationOperationId: undefined,
    }).success,
  ).toBe(false);
});

it.each(['oldFingerprint', 'oldReference', 'newReference'] as const)(
  'rejects duplicate %s across the reviewed bundle',
  (field) => {
    const value = request();
    value.replacements[1]![field] = value.replacements[0]![field];
    expect(workloadSigningHandoverRequestSchema.safeParse(value).success).toBe(false);
  },
);

it('rejects reusing another predecessor reference or changing canonical key order', () => {
  const value = request();
  value.replacements[1]!.newReference = value.replacements[0]!.oldReference;
  expect(workloadSigningHandoverRequestSchema.safeParse(value).success).toBe(false);
  expect(
    workloadSigningHandoverRequestSchema.safeParse({
      ...request(),
      replacements: request().replacements.reverse(),
    }).success,
  ).toBe(false);
});

it.each(['0', '01', '-1', 'not-an-epoch', '18446744073709551616'])(
  'rejects key epoch %s',
  (epoch) => {
    const value = request();
    value.replacements[0]!.expectedKeyEpoch = epoch;
    expect(workloadSigningHandoverRequestSchema.safeParse(value).success).toBe(false);
  },
);

it('rejects empty or excessive bundles and non-signing secret references', () => {
  const value = request();
  expect(
    workloadSigningHandoverRequestSchema.safeParse({ ...value, replacements: [] }).success,
  ).toBe(false);
  expect(
    workloadSigningHandoverRequestSchema.safeParse({
      ...value,
      replacements: Array.from({ length: 65 }, () => value.replacements[0]),
    }).success,
  ).toBe(false);
  value.replacements[0]!.newReference = 'file:///tmp/private-key.pem';
  expect(workloadSigningHandoverRequestSchema.safeParse(value).success).toBe(false);
});
