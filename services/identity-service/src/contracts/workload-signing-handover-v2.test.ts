import { describe, expect, it } from 'vitest';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import { businessSigningPurpose } from '../domain/business-signing-provider.js';
import { workloadSigningHandoverRequestSchema } from './workload-signing-handover.js';
import {
  workloadSigningHandoverRequestV2Schema,
  type WorkloadSigningHandoverRequestV2,
} from './workload-signing-handover-v2.js';

const id = (n: number) => '01a10000-0000-7000-8000-' + n.toString().padStart(12, '0');
const digest = (n: number) => 'sha256:' + n.toString(16).padStart(64, '0');
function replacement(n: number): WorkloadSigningHandoverRequestV2['replacements'][number] {
  return {
    oldFingerprint: digest(n),
    oldTrustDigest: digest(n + 1000),
    expectedKeyEpoch: '3',
    oldReference: `secret://local/receipt-old-${n}#1`,
    newReference: `secret://local/receipt-next-${n}#1`,
    signerRole: n === 6 ? ('LIFECYCLE_EVIDENCE' as const) : ('BUSINESS_EFFECT' as const),
    purpose: businessSigningPurpose,
  };
}
function request(): WorkloadSigningHandoverRequestV2 {
  return {
    schemaVersion: 2,
    actionIntentId: signingRotationActions.create,
    actionIntentDigest: digest(5000),
    environmentId: 'synthetic-repaired-workspace',
    predecessorCredentialId: id(1),
    successorCredentialId: id(2),
    credentialRotationOperationId: id(3),
    replacements: Array.from({ length: 6 }, (_, index) => replacement(index + 1)),
    reason: 'Replace the remaining receipt keys and preserve the completed envelope repair.',
    carriedEnvelope: {
      disposition: 'CARRY_COMPLETED_371_RECOVERY',
      purpose: identityEnvelopeContext.purpose,
      profileDigest: identityEnvelopeSigningProfileDigest,
      signerId: digest(100),
      trustDigest: digest(200),
      selectionAdmissionVersion: '2',
      recoveryId: id(10),
      rotationId: id(11),
      completionOperationId: id(12),
      leaseClosureOperationId: id(13),
      reviewOperationId: id(14),
    },
  };
}

it('names six receipt replacements and one native envelope repair without asserting verified source state', () => {
  const input = request();
  expect(workloadSigningHandoverRequestV2Schema.parse(input)).toEqual(input);
  expect(input.replacements.map((key) => key.signerRole)).toEqual([
    'BUSINESS_EFFECT',
    'BUSINESS_EFFECT',
    'BUSINESS_EFFECT',
    'BUSINESS_EFFECT',
    'BUSINESS_EFFECT',
    'LIFECYCLE_EVIDENCE',
  ]);
});

it('keeps the original all-replacement version-one contract separate', () => {
  const { carriedEnvelope: _carry, ...base } = request();
  const original = {
    ...base,
    schemaVersion: 1,
    replacements: [
      ...base.replacements,
      {
        oldFingerprint: digest(7),
        oldTrustDigest: digest(1007),
        expectedKeyEpoch: '3',
        oldReference: 'secret://local/envelope-old#1',
        newReference: 'secret://local/envelope-next#1',
        signerRole: 'IDENTITY_ENVELOPE',
        purpose: identityEnvelopeContext.purpose,
      },
    ],
  };
  expect(workloadSigningHandoverRequestSchema.parse(original)).toEqual(original);
  expect(workloadSigningHandoverRequestSchema.safeParse(request()).success).toBe(false);
  expect(
    workloadSigningHandoverRequestSchema.safeParse({ ...original, carriedEnvelope: _carry })
      .success,
  ).toBe(false);
  expect(workloadSigningHandoverRequestV2Schema.safeParse(original).success).toBe(false);
});

it('preserves the original total key bound when one slot carries the repaired envelope', () => {
  const input = request();
  input.replacements = Array.from({ length: 63 }, (_, index) => replacement(index + 1));
  expect(workloadSigningHandoverRequestV2Schema.safeParse(input).success).toBe(true);
  input.replacements.push(replacement(64));
  expect(workloadSigningHandoverRequestV2Schema.safeParse(input).success).toBe(false);
  const { carriedEnvelope: _carry, ...original } = input;
  expect(_carry.purpose).toBe(identityEnvelopeContext.purpose);
  expect(
    workloadSigningHandoverRequestSchema.safeParse({ ...original, schemaVersion: 1 }).success,
  ).toBe(true);
});

it.each(['1', '18446744073709551615'])(
  'accepts an unchanged carried selection version %s',
  (version) => {
    const input = request();
    input.carriedEnvelope.selectionAdmissionVersion = version;
    expect(
      workloadSigningHandoverRequestV2Schema.parse(input).carriedEnvelope.selectionAdmissionVersion,
    ).toBe(version);
  },
);

const mutations: [string, (input: WorkloadSigningHandoverRequestV2) => void][] = [
  [
    'same predecessor and successor',
    (r) => {
      r.successorCredentialId = r.predecessorCredentialId;
    },
  ],
  [
    'duplicate predecessor fingerprint',
    (r) => {
      r.replacements[1]!.oldFingerprint = r.replacements[0]!.oldFingerprint;
    },
  ],
  [
    'duplicate old reference',
    (r) => {
      r.replacements[1]!.oldReference = r.replacements[0]!.oldReference;
    },
  ],
  [
    'duplicate new reference',
    (r) => {
      r.replacements[1]!.newReference = r.replacements[0]!.newReference;
    },
  ],
  [
    'new reference reuses another old reference',
    (r) => {
      r.replacements[0]!.newReference = r.replacements[1]!.oldReference;
    },
  ],
  [
    'unordered replacements',
    (r) => {
      r.replacements.reverse();
    },
  ],
  [
    'empty replacements',
    (r) => {
      r.replacements = [];
    },
  ],
  [
    'carried fingerprint also replaced',
    (r) => {
      r.carriedEnvelope.signerId = r.replacements[0]!.oldFingerprint;
    },
  ],
  [
    'carried trust digest also replaced',
    (r) => {
      r.carriedEnvelope.trustDigest = r.replacements[0]!.oldTrustDigest;
    },
  ],
  [
    'envelope replacement in carry mode',
    (r) => {
      Object.assign(r.replacements[0]!, {
        signerRole: 'IDENTITY_ENVELOPE',
        purpose: identityEnvelopeContext.purpose,
      });
    },
  ],
  [
    'arbitrary carry purpose',
    (r) => {
      Object.assign(r.carriedEnvelope, { purpose: businessSigningPurpose });
    },
  ],
  [
    'arbitrary carry disposition',
    (r) => {
      Object.assign(r.carriedEnvelope, { disposition: 'CARRY_CURRENT_KEY' });
    },
  ],
  [
    'different profile',
    (r) => {
      Object.assign(r.carriedEnvelope, { profileDigest: digest(99) });
    },
  ],
  [
    'completion reused for closure',
    (r) => {
      r.carriedEnvelope.leaseClosureOperationId = r.carriedEnvelope.completionOperationId;
    },
  ],
  [
    'completion reused for review',
    (r) => {
      r.carriedEnvelope.reviewOperationId = r.carriedEnvelope.completionOperationId;
    },
  ],
  [
    'closure reused for review',
    (r) => {
      r.carriedEnvelope.reviewOperationId = r.carriedEnvelope.leaseClosureOperationId;
    },
  ],
  [
    'invalid recovery ID',
    (r) => {
      r.carriedEnvelope.recoveryId = 'not-a-recovery';
    },
  ],
  [
    'invalid rotation ID',
    (r) => {
      r.carriedEnvelope.rotationId = 'not-a-rotation';
    },
  ],
  [
    'invalid completion ID',
    (r) => {
      r.carriedEnvelope.completionOperationId = 'not-an-operation';
    },
  ],
  [
    'invalid closure ID',
    (r) => {
      r.carriedEnvelope.leaseClosureOperationId = 'not-an-operation';
    },
  ],
  [
    'invalid review ID',
    (r) => {
      r.carriedEnvelope.reviewOperationId = 'not-an-operation';
    },
  ],
  [
    'invalid signer digest',
    (r) => {
      r.carriedEnvelope.signerId = 'sha256:untrusted';
    },
  ],
  [
    'invalid trust digest',
    (r) => {
      r.carriedEnvelope.trustDigest = 'sha256:untrusted';
    },
  ],
];
it.each(mutations)('rejects %s', (_name, mutate) => {
  const input = request();
  mutate(input);
  expect(workloadSigningHandoverRequestV2Schema.safeParse(input).success).toBe(false);
});

it.each(['0', '02', '-1', '2e1', '18446744073709551616'])(
  'rejects noncanonical or overflowing carried version %s',
  (version) => {
    const input = request();
    input.carriedEnvelope.selectionAdmissionVersion = version;
    expect(workloadSigningHandoverRequestV2Schema.safeParse(input).success).toBe(false);
  },
);

describe.each(['request', 'carry'] as const)('%s is a closed locator request', (level) => {
  it.each([
    'ready',
    'verified',
    'authority',
    'grants',
    'trust',
    'publicKeySpkiHex',
    'proofs',
    'lease',
  ])('rejects client-supplied %s', (field) => {
    const input = request();
    Object.assign(level === 'request' ? input : input.carriedEnvelope, { [field]: true });
    expect(workloadSigningHandoverRequestV2Schema.safeParse(input).success).toBe(false);
  });
});

it('requires exactly one carried envelope locator', () => {
  const { carriedEnvelope, ...input } = request();
  expect(workloadSigningHandoverRequestV2Schema.safeParse(input).success).toBe(false);
  expect(
    workloadSigningHandoverRequestV2Schema.safeParse({ ...input, carriedEnvelope: [] }).success,
  ).toBe(false);
  expect(
    workloadSigningHandoverRequestV2Schema.safeParse({
      ...input,
      carriedEnvelope: [carriedEnvelope, carriedEnvelope],
    }).success,
  ).toBe(false);
});
