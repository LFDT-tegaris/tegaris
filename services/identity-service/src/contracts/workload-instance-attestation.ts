import { z } from 'zod';
import { workloadRenewalDigest } from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  assertWorkloadAttestationData,
  workloadRenewalChallengeSchema,
  managedWorkloadAttestationStatementSchema,
  managedWorkloadAttestationEvidenceSchema,
} from './workload-renewal-attestation.js';
import {
  workloadInstanceAdmissionDefinitionSchema,
  workloadInstanceAdmissionDefinitionDigest,
} from './workload-instance-admission.js';

/** Initial enrollment is a distinct protocol. The preparation operation and
 * attempt are durable preflight identities, NOT the final338 business operation.
 * The subsequent atomic effect links the original preflight to its actual
 * governed operation. Neither this public descriptor nor IDs establish trust.
 * Only the future durable challenge owner issues randomBytes(32) and authenticates
 * the actual reservation, native registration and complete ARCHIVE history. */
export const workloadInstanceChallengeSchema = z
  .strictObject({
    domain: z.literal('pc.identity.workload-instance.challenge.v1'),
    version: z.literal(1),
    enrollmentPreparationOperationId: workloadRenewalChallengeSchema.shape.challengeId,
    enrollmentAttemptId: workloadRenewalChallengeSchema.shape.challengeId,
    challengeId: workloadRenewalChallengeSchema.shape.challengeId,
    approvalRequestId: workloadRenewalChallengeSchema.shape.challengeId,
    candidateDigest: workloadRenewalChallengeSchema.shape.policyDigest,
    definitionDigest: workloadRenewalChallengeSchema.shape.policyDigest,
    definition: workloadInstanceAdmissionDefinitionSchema,
    nonce: workloadRenewalChallengeSchema.shape.nonce,
    issuedAtNs: workloadRenewalChallengeSchema.shape.issuedAtNs,
    validUntilNs: workloadRenewalChallengeSchema.shape.validUntilNs,
  })
  .superRefine((value, context) => {
    const from = BigInt(value.issuedAtNs),
      until = BigInt(value.validUntilNs);
    const definition = value.definition;
    if (
      until <= from ||
      until - from > 120000000000n ||
      from < BigInt(Date.parse(definition.validFrom)) * 1000000n ||
      until > BigInt(Date.parse(definition.validUntil)) * 1000000n ||
      value.definitionDigest !== workloadInstanceAdmissionDefinitionDigest(definition) ||
      new Set([
        value.enrollmentPreparationOperationId,
        value.enrollmentAttemptId,
        value.challengeId,
        value.approvalRequestId,
        definition.familyReservationId,
        definition.familyId,
        definition.initialCredentialId,
      ]).size !== 7
    )
      context.addIssue({ code: 'custom', message: 'Invalid finite initial instance challenge' });
  });
export type WorkloadInstanceChallenge = z.infer<typeof workloadInstanceChallengeSchema>;

/** Finite bounds read from the actual current initial credential and original
 * approval by the installation owner. Parsing these public values grants neither
 * approval nor credential validity; final transaction-time fences still apply. */
export const workloadInstanceParentValiditySchema = z
  .strictObject({
    approvalRequestId: workloadRenewalChallengeSchema.shape.challengeId,
    initialCredentialValidFromNs: workloadRenewalChallengeSchema.shape.issuedAtNs,
    initialCredentialValidUntilNs: workloadRenewalChallengeSchema.shape.validUntilNs,
    approvalValidFromNs: workloadRenewalChallengeSchema.shape.issuedAtNs,
    approvalValidUntilNs: workloadRenewalChallengeSchema.shape.validUntilNs,
  })
  .refine(
    (value) =>
      BigInt(value.initialCredentialValidUntilNs) > BigInt(value.initialCredentialValidFromNs) &&
      BigInt(value.approvalValidUntilNs) > BigInt(value.approvalValidFromNs),
  );
export type WorkloadInstanceParentValidity = z.infer<typeof workloadInstanceParentValiditySchema>;

/** The public attestor key/profile can identify the same managed source, but
 * installation MUST independently qualify that source for INITIAL enrollment.
 * Routine profile selection alone grants no such capability. No new OpenPC
 * COSE purpose or hardware/native qualification is implied by Ed25519. */
export const managedWorkloadInstanceStatementSchema = z
  .strictObject({
    ...managedWorkloadAttestationStatementSchema.shape,
    domain: z.literal('pc.identity.workload-instance.managed-attestation.v1'),
    challenge: workloadInstanceChallengeSchema,
    nativeObservationDigest: workloadRenewalChallengeSchema.shape.policyDigest,
  })
  .refine((value) => BigInt(value.validUntilNs) > BigInt(value.issuedAtNs));
export type ManagedWorkloadInstanceStatement = z.infer<
  typeof managedWorkloadInstanceStatementSchema
>;
const evidenceSchema = z.strictObject({
  statement: managedWorkloadInstanceStatementSchema,
  signatureBase64: managedWorkloadAttestationEvidenceSchema.shape.signatureBase64,
});

function encode<T>(schema: z.ZodType<T>, value: unknown): Buffer {
  assertWorkloadAttestationData(value);
  return Buffer.from(canonicalDefinitionJson(schema.parse(value)));
}
export function encodeWorkloadInstanceChallenge(value: WorkloadInstanceChallenge): Buffer {
  return encode(workloadInstanceChallengeSchema, value);
}
export function workloadInstanceChallengeDigest(value: WorkloadInstanceChallenge): string {
  return workloadRenewalDigest(encodeWorkloadInstanceChallenge(value));
}
export function encodeManagedWorkloadInstanceStatement(
  value: ManagedWorkloadInstanceStatement,
): Buffer {
  return encode(managedWorkloadInstanceStatementSchema, value);
}

const typedArrayLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  'length',
)!.get!;
const typedArraySet = Uint8Array.prototype.set;
/** Own the only binary input before any decoding, signature or digest use.
 * Never invoke input length/copy/slice/constructor/species or custom methods. */
export function snapshotWorkloadInstanceEvidence(value: Buffer): Buffer {
  if (!Buffer.isBuffer(value) || Object.getPrototypeOf(value) !== Buffer.prototype)
    throw new Error('Invalid initial instance evidence');
  const size = Reflect.apply(typedArrayLength, value, []) as number;
  if (size < 1 || size > 16384) throw new Error('Invalid initial instance evidence');
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== size ||
    keys.some((key) => typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(key))
  )
    throw new Error('Invalid initial instance binary properties');
  const copy = Buffer.alloc(size);
  Reflect.apply(typedArraySet, copy, [value]);
  return copy;
}
/** Parsed data alone is not authentication. The verifier snapshots first and
 * joins independent trusted expectations before returning historical evidence. */
export function decodeManagedWorkloadInstanceEvidence(bytes: Buffer) {
  const snapshot = snapshotWorkloadInstanceEvidence(bytes);
  const value: unknown = JSON.parse(snapshot.toString('utf8'));
  if (!encode(evidenceSchema, value).equals(snapshot))
    throw new Error('Noncanonical initial instance evidence');
  return evidenceSchema.parse(value);
}
