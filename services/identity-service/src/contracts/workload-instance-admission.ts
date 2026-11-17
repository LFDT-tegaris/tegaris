import { z } from 'zod';
import { createHash } from 'node:crypto';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { workloadInstanceAdmissionOperation } from '@openpc/security-kernel';
import { preparedBusinessTransitionProfileForOperation } from '../../../../packages/security-kernel/src/business-transition/profiles-prepared.js';
import {
  transitionStatePreimage,
  type CborValue,
} from '@openpc/security-kernel/business-transition/state';
import { assertWorkloadAttestationData } from './workload-renewal-attestation.js';

const id = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const counter = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const positive = counter.refine((value) => value !== '0');
const nanos = counter.refine((value) => BigInt(value) % 1000n === 0n);
const instant = z.iso.datetime({ precision: 3 });

/** Stable human candidate only. All reservations, registration/instance IDs,
 * deployment, credential and policy inputs must be resolved by their actual
 * owners. UUIDs/hashes/schema success confer no admission or currentness.
 * Fresh one-use initial-instance witness is staged AFTER governance setup,
 * bound to this SAME candidate, and committed in the typed effect state.
 * The original credential is historical admission provenance; later routine
 * authentication follows the current family pointer, never this old leaf. */
export const workloadInstanceAdmissionDefinitionSchema = z
  .strictObject({
    version: z.literal(1),
    participantId: id,
    privacyDomainId: id,
    environmentId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u),
    familyReservationId: id,
    familyId: id,
    instanceRegistrationId: id,
    instanceRegistrationDigest: digest,
    instanceId: id,
    instanceGeneration: positive,
    deploymentBindingDigest: digest,
    principalId: id,
    workloadId: z
      .string()
      .regex(
        /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
    initialCredentialId: id,
    initialCredentialEpoch: positive,
    initialCredentialFingerprint: digest,
    policyId: id,
    policyRevision: positive,
    policyDigest: digest,
    issuerProfileDigest: digest,
    providerQualificationDigest: digest,
    attestationProfileDigest: digest,
    managedAttestorScopeDigest: digest,
    participantSecurityInvalidationEpoch: counter,
    validFrom: instant,
    validUntil: instant,
  })
  .superRefine((value, context) => {
    if (
      Date.parse(value.validUntil) <= Date.parse(value.validFrom) ||
      new Set([value.familyId, value.familyReservationId, value.initialCredentialId]).size !== 3
    )
      context.addIssue({
        code: 'custom',
        message: 'Invalid initial instance admission definition',
      });
  });
export type WorkloadInstanceAdmissionDefinition = z.infer<
  typeof workloadInstanceAdmissionDefinitionSchema
>;
export const workloadInstanceAdmissionProposalSchema = z.strictObject({
  requestId: z.uuidv7().regex(/^[0-9a-f-]+$/u),
  expectedRevision: z.literal('0'),
  definition: workloadInstanceAdmissionDefinitionSchema,
  reason: z
    .string()
    .min(10)
    .max(1024)
    .refine((value) => value.normalize('NFC') === value),
});
export function workloadInstanceAdmissionDefinitionBytes(
  input: WorkloadInstanceAdmissionDefinition,
): Buffer {
  assertWorkloadAttestationData(input);
  return Buffer.from(
    canonicalDefinitionJson(workloadInstanceAdmissionDefinitionSchema.parse(input)),
  );
}
export function workloadInstanceAdmissionDefinitionDigest(
  input: WorkloadInstanceAdmissionDefinition,
): string {
  return `sha256:${createHash('sha256').update(workloadInstanceAdmissionDefinitionBytes(input)).digest('hex')}`;
}

/** This shape is emitted only after an actual scoped durable owner joins the
 * admission, signed receipt, consumed witness/challenge, original operation and
 * parent evidence. Parsing caller JSON does NOT establish those joins.
 * No ACTIVE/current/admitted boolean or issuance/runtime capability is exposed. */
export const workloadInstanceAdmissionReadbackSchema = z
  .strictObject({
    catalogOperationId: z.literal('ID-OP-WORKLOAD-INSTANCE-ADMIT'),
    receiptProfileId: z.literal('pc.identity.workload-instance.admit.v1'),
    receiptProfileVersion: z.literal(1),
    receiptProfileDigest: digest,
    revision: z.literal('1'),
    definition: workloadInstanceAdmissionDefinitionSchema,
    definitionDigest: digest,
    instanceWitnessDigest: digest,
    consumedChallengeId: id,
    admissionOperationId: id,
    receiptId: id,
    receiptDigest: digest,
    businessAncestorsDigest: digest,
    initializedFamilySecurityEpoch: z.literal('0'),
    admittedAtNs: nanos,
    runtimePermission: z.literal('NONE'),
    readback: z.literal('HISTORICAL_ONLY'),
  })
  .superRefine((value, context) => {
    const profile = preparedBusinessTransitionProfileForOperation(value.catalogOperationId);
    if (
      !profile ||
      profile.profileId !== value.receiptProfileId ||
      profile.profileVersion !== value.receiptProfileVersion ||
      profile.profileDigest !== value.receiptProfileDigest ||
      value.definitionDigest !== workloadInstanceAdmissionDefinitionDigest(value.definition) ||
      BigInt(value.admittedAtNs) < BigInt(Date.parse(value.definition.validFrom)) * 1000000n ||
      BigInt(value.admittedAtNs) >= BigInt(Date.parse(value.definition.validUntil)) * 1000000n ||
      new Set([
        value.consumedChallengeId,
        value.admissionOperationId,
        value.receiptId,
        value.definition.familyReservationId,
        value.definition.familyId,
        value.definition.initialCredentialId,
      ]).size !== 6
    )
      context.addIssue({
        code: 'custom',
        message: 'Invalid historical instance admission readback',
      });
  });
export type WorkloadInstanceAdmissionReadback = z.infer<
  typeof workloadInstanceAdmissionReadbackSchema
>;

/** Pure typed state encoding only. ABSENT must be an explicit AUTHORITATIVE
 * scoped absence/reservation result, never undefined, a hidden row or an empty
 * query. PRESENT must be actual durable original readback. This function cannot
 * authenticate either; absent installation keeps the future composition closed. */
export function bindWorkloadInstanceAdmissionSnapshot(
  scope: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly familyId: string;
  },
  input:
    | { readonly kind: 'ABSENT'; readonly familyReservationId: string }
    | { readonly kind: 'PRESENT'; readonly record: WorkloadInstanceAdmissionReadback },
) {
  assertWorkloadAttestationData(scope);
  assertWorkloadAttestationData(input);
  const checkedScope = z
    .strictObject({ participantId: id, privacyDomainId: id, familyId: id })
    .parse(scope);
  const snapshot = z
    .discriminatedUnion('kind', [
      z.strictObject({ kind: z.literal('ABSENT'), familyReservationId: id }),
      z.strictObject({
        kind: z.literal('PRESENT'),
        record: workloadInstanceAdmissionReadbackSchema,
      }),
    ])
    .parse(input);
  const operation = workloadInstanceAdmissionOperation;
  const profile = preparedBusinessTransitionProfileForOperation(operation.catalogOperationId);
  if (
    !profile ||
    profile.actionIntentId !== operation.actionIntentId ||
    profile.aggregateType !== operation.aggregateType ||
    profile.profileVersion !== 1
  )
    throw new Error('Initial instance admission profile unavailable');
  const uuid = (value: string) => Buffer.from(value.replaceAll('-', ''), 'hex');
  let projection = new Map<number, CborValue>();
  if (snapshot.kind === 'PRESENT') {
    const record = snapshot.record;
    if (
      record.definition.participantId !== checkedScope.participantId ||
      record.definition.privacyDomainId !== checkedScope.privacyDomainId ||
      record.definition.familyId !== checkedScope.familyId
    )
      throw new Error('Initial instance admission scope mismatch');
    projection = new Map<number, CborValue>([
      [0, Buffer.from(record.definitionDigest.slice(7), 'hex')],
      [1, Buffer.from(record.instanceWitnessDigest.slice(7), 'hex')],
      [2, uuid(record.consumedChallengeId)],
      [3, uuid(record.admissionOperationId)],
      [4, Buffer.from(record.businessAncestorsDigest.slice(7), 'hex')],
      [5, BigInt(record.definition.participantSecurityInvalidationEpoch)],
      [6, BigInt(record.admittedAtNs)],
      [7, BigInt(record.initializedFamilySecurityEpoch)],
    ]);
  } else if (snapshot.familyReservationId === checkedScope.familyId)
    throw new Error('Invalid distinct family reservation');
  const existence = snapshot.kind === 'PRESENT' ? (1 as const) : (0 as const);
  const revision = snapshot.kind === 'PRESENT' ? 1n : 0n;
  const preimage = transitionStatePreimage(
    {
      profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
      participantId: checkedScope.participantId,
      privacyDomainId: checkedScope.privacyDomainId,
      aggregateType: operation.aggregateType,
      aggregateId: checkedScope.familyId,
    },
    existence,
    revision,
    projection,
  );
  return {
    preimage,
    reference: { existence, revision, stateDigest: createHash('sha256').update(preimage).digest() },
  };
}
