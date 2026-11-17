import { z } from 'zod';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { workloadRenewalDigest } from '@openpc/security-kernel';

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
const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u);
const base64 = (length: number) =>
  z
    .string()
    .max(length)
    .refine((value) => Buffer.from(value, 'base64').toString('base64') === value);
const nonce = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/u)
  .refine(
    (value) =>
      Buffer.from(value, 'base64url').length === 32 &&
      Buffer.from(value, 'base64url').toString('base64url') === value,
  );

/** Public descriptor only. The issuing durable owner must generate nonce with
 * randomBytes(32), persist the actual family security and latest ARCHIVE fences,
 * and atomically consume this exact descriptor with the admitted original.
 * Revisions and these public values never establish current authority. */
export const workloadRenewalChallengeSchema = z
  .strictObject({
    domain: z.literal('pc.identity.workload-renewal.challenge.v1'),
    version: z.literal(1),
    environmentId: identifier,
    participantId: id,
    privacyDomainId: id,
    principalId: id,
    workloadId: z
      .string()
      .regex(
        /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
    familyId: id,
    instanceId: id,
    instanceGeneration: positive,
    familySecurityEpoch: counter,
    participantSecurityInvalidationEpoch: counter,
    renewalId: id,
    predecessorCredentialId: id,
    predecessorGeneration: positive,
    expectedFamilyRevision: positive,
    policyId: id,
    policyRevision: positive,
    policyDigest: digest,
    attestationProfileDigest: digest,
    managedAttestorScopeDigest: digest,
    issuerProfileDigest: digest,
    providerQualificationDigest: digest,
    newKeyDigest: digest,
    challengeId: id,
    nonce,
    requestedCertificateNotBeforeNs: nanos,
    requestedCertificateNotAfterNs: nanos,
    issuedAtNs: nanos,
    validUntilNs: nanos,
  })
  .superRefine((value, context) => {
    const start = BigInt(value.issuedAtNs),
      end = BigInt(value.validUntilNs);
    const from = BigInt(value.requestedCertificateNotBeforeNs),
      until = BigInt(value.requestedCertificateNotAfterNs);
    if (
      !(
        end > start &&
        end - start <= 120000000000n &&
        until > from &&
        until - from <= 86400000000000n &&
        from % 1000000000n === 0n &&
        until % 1000000000n === 0n
      ) ||
      new Set([value.challengeId, value.renewalId, value.predecessorCredentialId]).size !== 3
    )
      context.addIssue({ code: 'custom', message: 'Invalid finite renewal challenge' });
  });
export type WorkloadRenewalChallenge = z.infer<typeof workloadRenewalChallengeSchema>;

/** Qualification/key/lifecycle and independent custody must be authenticated
 * by installation composition. Parsing or hashing this public profile does not
 * qualify an attestor. This external protocol is not hardware attestation or a
 * newly registered OpenPC COSE purpose. */
export const managedWorkloadAttestationProfileSchema = z
  .strictObject({
    domain: z.literal('pc.identity.workload-renewal.managed-attestor-profile.v1'),
    version: z.literal(1),
    environmentId: identifier,
    issuer: identifier,
    audience: identifier,
    managedAttestorScopeDigest: digest,
    publicKeySpkiDerBase64: base64(128),
    maximumEvidenceLifetimeSeconds: z.number().int().min(1).max(120),
    validFromNs: nanos,
    validUntilNs: nanos,
  })
  .refine((value) => BigInt(value.validUntilNs) > BigInt(value.validFromNs));
export type ManagedWorkloadAttestationProfile = z.infer<
  typeof managedWorkloadAttestationProfileSchema
>;

export const managedWorkloadAttestationStatementSchema = z
  .strictObject({
    domain: z.literal('pc.identity.workload-renewal.managed-attestation.v1'),
    version: z.literal(1),
    issuer: identifier,
    audience: identifier,
    attestorKeyDigest: digest,
    attestationProfileDigest: digest,
    managedAttestorScopeDigest: digest,
    challenge: workloadRenewalChallengeSchema,
    challengeDigest: digest,
    issuedAtNs: nanos,
    validUntilNs: nanos,
  })
  .refine((value) => BigInt(value.validUntilNs) > BigInt(value.issuedAtNs));
export type ManagedWorkloadAttestationStatement = z.infer<
  typeof managedWorkloadAttestationStatementSchema
>;
export const managedWorkloadAttestationEvidenceSchema = z.strictObject({
  statement: managedWorkloadAttestationStatementSchema,
  signatureBase64: base64(88).refine((value) => Buffer.from(value, 'base64').length === 64),
});

/** Reject accessors, symbols, hidden properties and exotic values before a
 * schema or canonical encoder reads any caller object. These contracts contain
 * only plain records and primitives; they have no array or binary fields. */
export function assertWorkloadAttestationData(value: unknown, depth = 0): void {
  if (depth > 4) throw new Error('Invalid workload attestation data');
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return;
  if (typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error('Invalid workload attestation data');
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !descriptor?.enumerable || !('value' in descriptor))
      throw new Error('Invalid workload attestation data');
    assertWorkloadAttestationData(descriptor.value, depth + 1);
  }
}
function encode<T>(schema: z.ZodType<T>, value: unknown): Buffer {
  assertWorkloadAttestationData(value);
  return Buffer.from(canonicalDefinitionJson(schema.parse(value)));
}
export function encodeWorkloadRenewalChallenge(value: WorkloadRenewalChallenge): Buffer {
  return encode(workloadRenewalChallengeSchema, value);
}
export function workloadRenewalChallengeDigest(value: WorkloadRenewalChallenge): string {
  return workloadRenewalDigest(encodeWorkloadRenewalChallenge(value));
}
export function encodeManagedWorkloadAttestationProfile(
  value: ManagedWorkloadAttestationProfile,
): Buffer {
  return encode(managedWorkloadAttestationProfileSchema, value);
}
export function managedWorkloadAttestationProfileDigest(
  value: ManagedWorkloadAttestationProfile,
): string {
  return workloadRenewalDigest(encodeManagedWorkloadAttestationProfile(value));
}
export function encodeManagedWorkloadAttestationStatement(
  value: ManagedWorkloadAttestationStatement,
): Buffer {
  return encode(managedWorkloadAttestationStatementSchema, value);
}
export function decodeManagedWorkloadAttestationEvidence(bytes: Buffer) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 16384)
    throw new Error('Invalid workload attestation evidence');
  const value: unknown = JSON.parse(bytes.toString('utf8'));
  const encoded = encode(managedWorkloadAttestationEvidenceSchema, value);
  if (!encoded.equals(bytes)) throw new Error('Noncanonical workload attestation evidence');
  return managedWorkloadAttestationEvidenceSchema.parse(value);
}
