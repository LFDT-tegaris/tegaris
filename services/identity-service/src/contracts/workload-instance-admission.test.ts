import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { businessTransitionProfileForOperation } from '@openpc/security-kernel';
import { preparedBusinessTransitionProfileForOperation } from '../../../../packages/security-kernel/src/business-transition/profiles-prepared.js';
import { decodeCbor } from '../../../../packages/security-kernel/src/business-transition/cbor.js';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  bindWorkloadInstanceAdmissionSnapshot,
  workloadInstanceAdmissionDefinitionBytes,
  workloadInstanceAdmissionDefinitionDigest,
  workloadInstanceAdmissionDefinitionSchema,
  workloadInstanceAdmissionProposalSchema,
  workloadInstanceAdmissionReadbackSchema,
  type WorkloadInstanceAdmissionDefinition,
  type WorkloadInstanceAdmissionReadback,
} from './workload-instance-admission.js';

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const digest = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
const definition = (): WorkloadInstanceAdmissionDefinition => ({
  version: 1,
  participantId: id(1),
  privacyDomainId: id(2),
  environmentId: 'local-qualification',
  familyReservationId: id(3),
  familyId: id(4),
  instanceRegistrationId: id(5),
  instanceRegistrationDigest: digest(1),
  instanceId: id(6),
  instanceGeneration: '1',
  deploymentBindingDigest: digest(2),
  principalId: id(7),
  workloadId: `urn:openpc:workload:${id(8)}`,
  initialCredentialId: id(9),
  initialCredentialEpoch: '2',
  initialCredentialFingerprint: digest(3),
  policyId: id(10),
  policyRevision: '3',
  policyDigest: digest(4),
  issuerProfileDigest: digest(5),
  providerQualificationDigest: digest(6),
  attestationProfileDigest: digest(7),
  managedAttestorScopeDigest: digest(8),
  participantSecurityInvalidationEpoch: '0',
  validFrom: '2026-10-04T00:00:00.000Z',
  validUntil: '2026-10-05T00:00:00.000Z',
});
const record = (): WorkloadInstanceAdmissionReadback => {
  const value = definition(),
    profile = preparedBusinessTransitionProfileForOperation('ID-OP-WORKLOAD-INSTANCE-ADMIT')!;
  return {
    catalogOperationId: 'ID-OP-WORKLOAD-INSTANCE-ADMIT',
    receiptProfileId: 'pc.identity.workload-instance.admit.v1',
    receiptProfileVersion: 1,
    receiptProfileDigest: profile.profileDigest,
    revision: '1',
    definition: value,
    definitionDigest: workloadInstanceAdmissionDefinitionDigest(value),
    instanceWitnessDigest: digest(9),
    consumedChallengeId: id(11),
    admissionOperationId: id(12),
    receiptId: id(13),
    receiptDigest: digest(10),
    businessAncestorsDigest: digest(11),
    initializedFamilySecurityEpoch: '0',
    admittedAtNs: (BigInt(Date.parse(value.validFrom)) * 1000000n).toString(),
    runtimePermission: 'NONE',
    readback: 'HISTORICAL_ONLY',
  };
};
const scope = () => {
  const value = definition();
  return {
    participantId: value.participantId,
    privacyDomainId: value.privacyDomainId,
    familyId: value.familyId,
  };
};

it('binds a stable initial candidate without short-lived witness or manufactured authority', () => {
  const value = definition();
  expect(workloadInstanceAdmissionDefinitionSchema.parse(value)).toEqual(value);
  const proposal = {
    requestId: id(14),
    expectedRevision: '0',
    definition: value,
    reason: 'Admit isolated managed instance',
  };
  expect(workloadInstanceAdmissionProposalSchema.parse(proposal)).toEqual(proposal);
  for (const field of [
    'instanceWitnessDigest',
    'challengeId',
    'attestationEvidence',
    'admitted',
    'ACTIVE',
    'currentFamilySecurityEpoch',
    'runtimeCapabilities',
    'approved',
    'ready',
    'sessionId',
    'recoveryLeaseId',
    'privateKey',
  ])
    expect(
      workloadInstanceAdmissionDefinitionSchema.safeParse({ ...value, [field]: true }).success,
    ).toBe(false);
  for (const revision of ['1', '2', '01'])
    expect(
      workloadInstanceAdmissionProposalSchema.safeParse({ ...proposal, expectedRevision: revision })
        .success,
    ).toBe(false);
});

it('commits every stable field without confusing original transport provenance with a future current credential', () => {
  const value = definition(),
    original = workloadInstanceAdmissionDefinitionDigest(value);
  for (const [field, before] of Object.entries(value)) {
    if (field === 'version') continue;
    let after =
      typeof before === 'string' && before.startsWith('sha256:')
        ? digest(90)
        : typeof before === 'string' && before.startsWith('urn:openpc:workload:')
          ? `urn:openpc:workload:${id(90)}`
          : typeof before === 'string' && /^[0-9a-f-]{36}$/u.test(before)
            ? id(90)
            : field === 'validFrom'
              ? '2026-10-04T00:00:01.000Z'
              : field === 'validUntil'
                ? '2026-10-05T00:00:01.000Z'
                : field === 'environmentId'
                  ? 'another-environment'
                  : '9';
    if (after === before) after = '8';
    expect(workloadInstanceAdmissionDefinitionDigest({ ...value, [field]: after })).not.toBe(
      original,
    );
  }
  expect(
    workloadInstanceAdmissionDefinitionDigest(
      Object.fromEntries(Object.entries(value).reverse()) as typeof value,
    ),
  ).toBe(original);
  expect(workloadInstanceAdmissionDefinitionBytes(value).toString('utf8')).toBe(
    canonicalDefinitionJson(value),
  );
});

it.each([
  { instanceGeneration: '0' },
  { policyRevision: '01' },
  { initialCredentialEpoch: '0' },
  { participantSecurityInvalidationEpoch: '18446744073709551616' },
  { familyId: id(3) },
  { familyId: id(9) },
  { validUntil: '2026-10-04T00:00:00.000Z' },
  { deploymentBindingDigest: digest(2).toUpperCase() },
  { workloadId: 'caller-pod-label' },
  { environmentId: 'scope/*' },
])('rejects malformed or conflicting initial definition %j', (patch) => {
  expect(
    workloadInstanceAdmissionDefinitionSchema.safeParse({ ...definition(), ...patch }).success,
  ).toBe(false);
});

it('requires explicit scoped absence and full historical receipt links; no missing-owner zero/default success', () => {
  const absent = bindWorkloadInstanceAdmissionSnapshot(scope(), {
    kind: 'ABSENT',
    familyReservationId: id(3),
  });
  expect(absent.reference).toMatchObject({ existence: 0, revision: 0n });
  expect(() => bindWorkloadInstanceAdmissionSnapshot(scope(), undefined as never)).toThrow();
  expect(() => bindWorkloadInstanceAdmissionSnapshot(scope(), {} as never)).toThrow();
  expect(() =>
    bindWorkloadInstanceAdmissionSnapshot(scope(), { kind: 'ABSENT', familyReservationId: id(4) }),
  ).toThrow();
  expect(
    workloadInstanceAdmissionReadbackSchema.safeParse({ definition: definition(), admitted: true })
      .success,
  ).toBe(false);
  const valid = record();
  expect(workloadInstanceAdmissionReadbackSchema.parse(valid)).toEqual(valid);
  for (const field of [
    'receiptId',
    'receiptDigest',
    'admissionOperationId',
    'consumedChallengeId',
    'instanceWitnessDigest',
    'businessAncestorsDigest',
    'receiptProfileDigest',
  ]) {
    const incomplete = { ...valid } as Record<string, unknown>;
    delete incomplete[field];
    expect(workloadInstanceAdmissionReadbackSchema.safeParse(incomplete).success).toBe(false);
  }
});

it('keeps the uninstalled initial profile passive while installed policy profiles still resolve normally', () => {
  expect(businessTransitionProfileForOperation('ID-OP-WORKLOAD-INSTANCE-ADMIT')).toBeUndefined();
  const profile = preparedBusinessTransitionProfileForOperation('ID-OP-WORKLOAD-INSTANCE-ADMIT')!;
  expect(profile.profileDigest).toBe(
    'sha256:501e845d224e93d74175efe32900b2f6ef1f0a5db099107d28c491fc223f81f3',
  );
  expect(
    preparedBusinessTransitionProfileForOperation('ID-OP-WORKLOAD-INSTANCE-ADMIT', 2),
  ).toBeUndefined();
  expect(
    businessTransitionProfileForOperation('ID-OP-WORKLOAD-RENEWAL-POLICY-CREATE'),
  ).toBeDefined();
  expect(
    preparedBusinessTransitionProfileForOperation('ID-OP-WORKLOAD-RENEWAL-POLICY-CREATE'),
  ).toBeUndefined();
});

it('matches an independently ordered typed338 state oracle and immutable one-effect profile cardinality', () => {
  const value = record(),
    profile = preparedBusinessTransitionProfileForOperation(value.catalogOperationId)!;
  const state = bindWorkloadInstanceAdmissionSnapshot(scope(), { kind: 'PRESENT', record: value });
  const uuid = (value: string) => Buffer.from(value.replaceAll('-', ''), 'hex');
  expect(decodeCbor(state.preimage)).toEqual([
    'pc.control.transition-state.v1',
    Buffer.from(profile.profileDigest.slice(7), 'hex'),
    uuid(value.definition.participantId),
    uuid(value.definition.privacyDomainId),
    'workload-instance-admission',
    uuid(value.definition.familyId),
    1n,
    1n,
    new Map<number, Buffer | bigint>([
      [0, Buffer.from(value.definitionDigest.slice(7), 'hex')],
      [1, Buffer.from(value.instanceWitnessDigest.slice(7), 'hex')],
      [2, uuid(value.consumedChallengeId)],
      [3, uuid(value.admissionOperationId)],
      [4, Buffer.from(value.businessAncestorsDigest.slice(7), 'hex')],
      [5, 0n],
      [6, BigInt(value.admittedAtNs)],
      [7, 0n],
    ]),
  ]);
  expect(state.reference.stateDigest).toEqual(createHash('sha256').update(state.preimage).digest());
  const metadata = JSON.parse(
    readFileSync(
      new URL(
        '../../../../schemas/canonical/business-transition-profiles/workload-instance-admit-v1.json',
        import.meta.url,
      ),
      'utf8',
    ),
  );
  expect(metadata.events).toHaveLength(1);
  expect(metadata.events[0].cardinality).toBe(1);
  expect(metadata.schemaDefinitionDigest).toBe(
    'sha256:41a877ca7e00e74f32c8becf8daee38f26c12ab9d9dcf6ff80ed8e75608b3c1f',
  );
  expect(metadata.sequenceNamespace).toBe('CONTROL_BUSINESS_TRANSITION_V1');
});

it('rejects foreign scope, modified candidate, manual receipts and premature runtime/admission claims', () => {
  const original = record();
  for (const patch of [
    { participantId: id(90) },
    { privacyDomainId: id(90) },
    { familyId: id(90) },
  ])
    expect(() =>
      bindWorkloadInstanceAdmissionSnapshot(
        { ...scope(), ...patch },
        { kind: 'PRESENT', record: original },
      ),
    ).toThrow();
  for (const changed of [
    { ...original, definition: { ...original.definition, instanceGeneration: '2' } },
    { ...original, catalogOperationId: 'ID-OP-WORKLOAD-ISSUE' },
    { ...original, receiptProfileId: 'pc.control.identity.workload-issue' },
    { ...original, receiptProfileDigest: digest(90) },
    { ...original, runtimePermission: 'CURRENT' },
    { ...original, readback: 'ADMITTED' },
    { ...original, initializedFamilySecurityEpoch: '1' },
    { ...original, consumedChallengeId: original.admissionOperationId },
  ])
    expect(workloadInstanceAdmissionReadbackSchema.safeParse(changed).success).toBe(false);
});

it('binds fresh witness and actual archive fence in effect without changing the approved stable candidate', () => {
  const original = record(),
    before = workloadInstanceAdmissionDefinitionDigest(original.definition);
  const first = bindWorkloadInstanceAdmissionSnapshot(scope(), {
    kind: 'PRESENT',
    record: original,
  });
  const refreshed = { ...original, instanceWitnessDigest: digest(90), consumedChallengeId: id(90) };
  expect(workloadInstanceAdmissionDefinitionDigest(refreshed.definition)).toBe(before);
  expect(
    bindWorkloadInstanceAdmissionSnapshot(scope(), { kind: 'PRESENT', record: refreshed }).reference
      .stateDigest,
  ).not.toEqual(first.reference.stateDigest);
  const changedDefinition = { ...original.definition, participantSecurityInvalidationEpoch: '1' };
  const changed = {
    ...original,
    definition: changedDefinition,
    definitionDigest: workloadInstanceAdmissionDefinitionDigest(changedDefinition),
  };
  expect(
    bindWorkloadInstanceAdmissionSnapshot(scope(), { kind: 'PRESENT', record: changed }).reference
      .stateDigest,
  ).not.toEqual(first.reference.stateDigest);
});

it('rejects hidden fields/accessors before canonical candidate or state encoding', () => {
  let accessed = false;
  const value = definition();
  Object.defineProperty(value, 'environmentId', {
    enumerable: true,
    get() {
      accessed = true;
      return 'local-qualification';
    },
  });
  expect(() => workloadInstanceAdmissionDefinitionBytes(value)).toThrow();
  expect(accessed).toBe(false);
  const input = { kind: 'ABSENT', familyReservationId: id(3) };
  Object.defineProperty(input, 'installed', { enumerable: false, value: true });
  expect(() => bindWorkloadInstanceAdmissionSnapshot(scope(), input as never)).toThrow();
});
