import { z } from 'zod';

import {
  entityMetadataShape,
  evmAddressSchema,
  openPcUrnSchema,
  rfc3339MicrosUtcSchema,
  sha256DigestSchema,
  uint64StringSchema,
  uniqueStringsSchema,
} from './primitives.js';

export const participantStatusValues = [
  'PROVISIONING',
  'ACTIVE',
  'SUSPENDED',
  'TRANSFER_PENDING',
  'REVOKED',
  'OFFBOARDED',
] as const;
export const authorityEnvelopeStatusValues = [
  'DRAFT',
  'SUBMITTED',
  'APPROVED',
  'ACTIVE',
  'SUPERSEDED',
  'REVOKED',
] as const;
export const assignmentStatusValues = [
  'PROPOSED',
  'ACTIVE',
  'SUSPENDED',
  'REVOKED',
  'EXPIRED',
] as const;
export const delegationStatusValues = assignmentStatusValues;
export const walletBindingStatusValues = ['PROPOSED', 'ACTIVE', 'REVOKED', 'EXPIRED'] as const;

export const participantSchema = z.strictObject({
  contractType: z.literal('Participant'),
  ...entityMetadataShape,
  status: z.enum(participantStatusValues),
  participantId: openPcUrnSchema,
  participantEpoch: uint64StringSchema,
  authorityEnvelopeId: openPcUrnSchema,
  privacyDomainId: openPcUrnSchema,
});

export const authorityEnvelopeSchema = z
  .strictObject({
    contractType: z.literal('AuthorityEnvelope'),
    ...entityMetadataShape,
    status: z.enum(authorityEnvelopeStatusValues),
    participantId: openPcUrnSchema,
    authorityEpoch: uint64StringSchema,
    envelopeDigest: sha256DigestSchema,
    scopeIds: uniqueStringsSchema(),
    capabilityIds: uniqueStringsSchema(),
    makerPrincipalId: openPcUrnSchema,
    checkerPrincipalId: openPcUrnSchema,
  })
  .refine(
    (envelope) => envelope.makerPrincipalId !== envelope.checkerPrincipalId,
    'maker and checker must be distinct',
  );

export const assignmentSchema = z
  .strictObject({
    contractType: z.literal('Assignment'),
    ...entityMetadataShape,
    status: z.enum(assignmentStatusValues),
    participantId: openPcUrnSchema,
    participantEpoch: uint64StringSchema,
    subjectId: openPcUrnSchema,
    roleId: openPcUrnSchema,
    scopeDigest: sha256DigestSchema,
    notBefore: rfc3339MicrosUtcSchema,
    notAfter: rfc3339MicrosUtcSchema,
  })
  .refine(
    (assignment) => assignment.notBefore < assignment.notAfter,
    'assignment time range is empty',
  );

export const delegationSchema = z
  .strictObject({
    contractType: z.literal('Delegation'),
    ...entityMetadataShape,
    status: z.enum(delegationStatusValues),
    participantId: openPcUrnSchema,
    delegationEpoch: uint64StringSchema,
    grantorId: openPcUrnSchema,
    granteeId: openPcUrnSchema,
    parentDelegationId: openPcUrnSchema.nullable(),
    grantableDigest: sha256DigestSchema,
    usableDigest: sha256DigestSchema,
    downwardProofDigest: sha256DigestSchema,
    notAfter: rfc3339MicrosUtcSchema,
  })
  .refine(
    (delegation) => delegation.grantorId !== delegation.granteeId,
    'self-delegation is forbidden',
  );

export const walletBindingSchema = z.strictObject({
  contractType: z.literal('WalletBinding'),
  ...entityMetadataShape,
  status: z.enum(walletBindingStatusValues),
  participantId: openPcUrnSchema,
  subjectId: openPcUrnSchema,
  chainId: uint64StringSchema,
  walletAddress: evmAddressSchema,
  bindingEpoch: uint64StringSchema,
  permissionEffect: z.literal('NONE_WITHOUT_EFFECTIVE_AUTHORITY'),
});

export type Participant = z.infer<typeof participantSchema>;
export type AuthorityEnvelope = z.infer<typeof authorityEnvelopeSchema>;
export type Assignment = z.infer<typeof assignmentSchema>;
export type Delegation = z.infer<typeof delegationSchema>;
export type WalletBinding = z.infer<typeof walletBindingSchema>;
