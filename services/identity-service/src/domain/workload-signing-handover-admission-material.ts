import { z } from 'zod';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
  type BusinessSigningTrust,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import { workloadSigningReplacementSchema } from '../contracts/workload-signing-handover.js';
import { handoverPossessionGenerationSchema } from './workload-signing-handover-possession.js';

export const handoverDigestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const handoverCounterSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
export const handoverEpochSchema = handoverCounterSchema.refine((value) => BigInt(value) > 0n);
export const handoverNanosSchema = handoverCounterSchema.refine(
  (value) => BigInt(value) % 1000n === 0n,
);
const base64 = z
  .string()
  .min(4)
  .max(131072)
  .refine((value) => Buffer.from(value, 'base64').toString('base64') === value);
const sourceFields = {
  oldTrustPreimageBase64: base64,
  oldCredentialEpoch: handoverEpochSchema,
  oldKeyValidFromNs: handoverNanosSchema,
  oldKeyValidUntilNs: handoverNanosSchema,
};
const sourceKey = z.discriminatedUnion('purpose', [
  workloadSigningReplacementSchema.options[0].extend(sourceFields),
  workloadSigningReplacementSchema.options[1].extend(sourceFields),
]);

/** The existing source document keeps its original version and bytes. Audience
 * is captured separately by the current credential owner for the candidate. */
export const handoverAdmissionSourceSchema = z.strictObject({
  schema: z.literal('pc.identity.workload-signing-handover.source.v1'),
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  environmentId: z.string().min(1).max(160),
  issuer: handoverPossessionGenerationSchema.shape.issuer,
  provenance: z.strictObject({
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    predecessorCredentialId: z.uuidv7(),
    predecessorCredentialEpoch: handoverEpochSchema,
    successorCredentialId: z.uuidv7(),
    successorCredentialEpoch: handoverEpochSchema,
    credentialRotationOperationId: z.uuidv7(),
    principalId: z.uuidv7(),
    makerPrincipalId: z.uuidv7(),
    checkerPrincipalId: z.uuidv7(),
    candidateDigest: handoverDigestSchema,
    evidenceDigest: handoverDigestSchema,
  }),
  keys: z.array(sourceKey).min(1).max(64),
  receiptSelections: z
    .array(
      z.strictObject({
        signerId: handoverDigestSchema,
        credentialId: z.uuidv7(),
        profileId: z.string().min(1).max(160),
        profileVersion: z.number().int().positive(),
        profileDigest: handoverDigestSchema,
        rowVersion: handoverEpochSchema,
        admissionVersion: handoverEpochSchema,
        fenceGeneration: handoverEpochSchema,
        fencedOperationId: z.null(),
      }),
    )
    .max(4096),
  envelopeSelections: z
    .array(
      z.strictObject({
        signerId: handoverDigestSchema,
        credentialId: z.uuidv7(),
        profileDigest: z.literal(identityEnvelopeSigningProfileDigest),
        admissionVersion: handoverEpochSchema,
      }),
    )
    .length(1),
});

const trustBase = {
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  environmentId: z.string().min(1).max(160),
  signerId: handoverDigestSchema,
  publicKeySpkiHex: z
    .string()
    .min(2)
    .max(4096)
    .regex(/^(?:[0-9a-f]{2})+$/u),
  workloadCredentialId: z.uuidv7(),
  workloadCredentialEpoch: handoverEpochSchema,
  keyEpoch: handoverEpochSchema,
  validFromNs: handoverNanosSchema,
  validUntilNs: handoverNanosSchema,
  admissionKind: z.enum(['BOOTSTRAP', 'GOVERNED']),
  admissionReference: z.string().min(1).max(256),
  admissionDigest: handoverDigestSchema,
  secretClass: z.literal('SECRET-SIGNING-KEY'),
  secretReference: z.string().min(1).max(331),
  secretVersion: z.string().min(1).max(96),
};
export const handoverAdmissionTrustSchema = z.discriminatedUnion('signerRole', [
  z.strictObject({
    ...trustBase,
    signerRole: z.enum(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE']),
    grants: z
      .array(
        z.strictObject({
          profileId: z.string().min(1).max(160),
          profileVersion: z.number().int().positive(),
          profileDigest: handoverDigestSchema,
          actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
          catalogOperationId: z.string().min(1).max(128),
        }),
      )
      .min(1)
      .max(64),
  }),
  z.strictObject({
    ...trustBase,
    signerRole: z.literal('IDENTITY_ENVELOPE'),
    workloadParticipantEpoch: handoverEpochSchema,
    workloadPrincipalEpoch: handoverEpochSchema,
    purpose: z.literal(identityEnvelopeContext.purpose),
    profileId: z.literal(identityEnvelopeSigningProfile.profileId),
    profileVersion: z.literal(1),
    profileDigest: z.literal(identityEnvelopeSigningProfileDigest),
  }),
]);
export type HandoverAdmissionTrust = z.infer<typeof handoverAdmissionTrustSchema>;
export type HandoverCapturedTrust =
  | { signerRole: 'BUSINESS_EFFECT' | 'LIFECYCLE_EVIDENCE'; trust: BusinessSigningTrust }
  | { signerRole: 'IDENTITY_ENVELOPE'; trust: IdentityEnvelopeSigningTrust };
const tagged = (bytes: Buffer) => 'sha256:' + bytes.toString('hex');

/** Public verification material only; never include a provider private key or
 * caller authority object in the immutable candidate. */
export function handoverAdmissionTrustDocument(
  input: HandoverCapturedTrust,
): HandoverAdmissionTrust {
  const trust = input.trust;
  const common = {
    participantId: trust.participantId,
    privacyDomainId: trust.privacyDomainId,
    environmentId: trust.environmentId,
    signerId: trust.signerId,
    publicKeySpkiHex: trust.publicKeySpkiDer.toString('hex'),
    workloadCredentialId: trust.workloadCredentialId,
    workloadCredentialEpoch: trust.workloadCredentialEpoch.toString(),
    keyEpoch: trust.keyEpoch.toString(),
    validFromNs: trust.validFromNs.toString(),
    validUntilNs: trust.validUntilNs.toString(),
    admissionKind: trust.admissionKind,
    admissionReference: trust.admissionReference,
    admissionDigest: tagged(trust.admissionDigest),
    secretClass: trust.secretClass,
    secretReference: trust.secretReference,
    secretVersion: trust.secretVersion,
  };
  return handoverAdmissionTrustSchema.parse(
    input.signerRole === 'IDENTITY_ENVELOPE'
      ? {
          ...common,
          signerRole: input.signerRole,
          workloadParticipantEpoch: input.trust.workloadParticipantEpoch.toString(),
          workloadPrincipalEpoch: input.trust.workloadPrincipalEpoch.toString(),
          purpose: input.trust.purpose,
          profileId: input.trust.profileId,
          profileVersion: input.trust.profileVersion,
          profileDigest: input.trust.profileDigest,
        }
      : {
          ...common,
          signerRole: input.signerRole,
          grants: input.trust.grants.map((grant) => ({
            ...grant,
            profileDigest: tagged(grant.profileDigest),
          })),
        },
  );
}

/** Reconstruct exactly the established kernel trust tuple; its canonical
 * preimage must still match the original source before it can be used. */
export function handoverAdmissionKernelTrust(input: HandoverAdmissionTrust): HandoverCapturedTrust {
  const value = handoverAdmissionTrustSchema.parse(input);
  const common = {
    participantId: value.participantId,
    privacyDomainId: value.privacyDomainId,
    environmentId: value.environmentId,
    signerId: value.signerId,
    publicKeySpkiDer: Buffer.from(value.publicKeySpkiHex, 'hex'),
    workloadCredentialId: value.workloadCredentialId,
    workloadCredentialEpoch: BigInt(value.workloadCredentialEpoch),
    keyEpoch: BigInt(value.keyEpoch),
    validFromNs: BigInt(value.validFromNs),
    validUntilNs: BigInt(value.validUntilNs),
    admissionKind: value.admissionKind,
    admissionReference: value.admissionReference,
    admissionDigest: Buffer.from(value.admissionDigest.slice(7), 'hex'),
    secretClass: value.secretClass,
    secretReference: value.secretReference,
    secretVersion: value.secretVersion,
  };
  return value.signerRole === 'IDENTITY_ENVELOPE'
    ? {
        signerRole: value.signerRole,
        trust: {
          ...common,
          workloadParticipantEpoch: BigInt(value.workloadParticipantEpoch),
          workloadPrincipalEpoch: BigInt(value.workloadPrincipalEpoch),
          purpose: value.purpose,
          profileId: value.profileId,
          profileVersion: value.profileVersion,
          profileDigest: value.profileDigest,
        },
      }
    : {
        signerRole: value.signerRole,
        trust: {
          ...common,
          grants: value.grants.map((grant) => ({
            ...grant,
            profileDigest: Buffer.from(grant.profileDigest.slice(7), 'hex'),
          })),
        },
      };
}
