import { z } from 'zod';

import {
  actionIntentIdSchema,
  entityMetadataShape,
  openPcUrnSchema,
  rfc3339MicrosUtcSchema,
  sha256DigestSchema,
  uint64StringSchema,
} from './primitives.js';

export const sessionCookieProfile =
  '__Host-openpc_session; Secure; HttpOnly; SameSite=Strict; Path=/' as const;

export const principalStatusValues = [
  'PROVISIONED',
  'ACTIVE',
  'SUSPENDED',
  'REVOKED',
  'OFFBOARDED',
] as const;
export const sessionStatusValues = [
  'AUTHENTICATING',
  'ACTIVE',
  'STEP_UP_REQUIRED',
  'REVOKED',
  'EXPIRED',
  'COMPROMISED',
] as const;
export const workloadCredentialStatusValues = [
  'ISSUED',
  'ACTIVE',
  'ROTATING',
  'REVOKED',
  'EXPIRED',
] as const;
export const mfaEvidenceStatusValues = [
  'CHALLENGE_ISSUED',
  'VERIFIED',
  'CONSUMED',
  'EXPIRED',
  'REVOKED',
] as const;
export const recoveryCaseStatusValues = [
  'REQUESTED',
  'CUSTODIAN_ONE_APPROVED',
  'CUSTODIAN_TWO_APPROVED',
  'LEASE_ACTIVE',
  'COMPLETED',
  'DENIED',
  'EXPIRED',
  'REVOKED',
] as const;
export const revocationRecordStatusValues = ['REQUESTED', 'COMMITTED', 'EVIDENCED'] as const;

export const principalSchema = z.strictObject({
  contractType: z.literal('Principal'),
  ...entityMetadataShape,
  status: z.enum(principalStatusValues),
  principalId: openPcUrnSchema,
  identityEpoch: uint64StringSchema,
  assurance: z.enum(['OIDC', 'OIDC_WEBAUTHN', 'WORKLOAD_MTLS', 'RECOVERY_PRINCIPAL']),
});

export const sessionSchema = z.strictObject({
  contractType: z.literal('Session'),
  ...entityMetadataShape,
  status: z.enum(sessionStatusValues),
  sessionId: openPcUrnSchema,
  principalId: openPcUrnSchema,
  participantId: openPcUrnSchema,
  participantEpoch: uint64StringSchema,
  sessionEpoch: uint64StringSchema,
  idleExpiresAt: rfc3339MicrosUtcSchema,
  absoluteExpiresAt: rfc3339MicrosUtcSchema,
  stepUpValidUntil: rfc3339MicrosUtcSchema.nullable(),
  refreshFamilyId: openPcUrnSchema,
  cookieProfile: z.literal(sessionCookieProfile),
});

export const workloadCredentialSchema = z.strictObject({
  contractType: z.literal('WorkloadCredential'),
  ...entityMetadataShape,
  status: z.enum(workloadCredentialStatusValues),
  credentialId: openPcUrnSchema,
  workloadId: openPcUrnSchema,
  participantId: openPcUrnSchema,
  workloadEpoch: uint64StringSchema,
  keyId: sha256DigestSchema,
  uriSan: z
    .string()
    .regex(
      /^urn:openpc:participant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    ),
  notBefore: rfc3339MicrosUtcSchema,
  notAfter: rfc3339MicrosUtcSchema,
  rotationDueAt: rfc3339MicrosUtcSchema,
  tlsVersion: z.literal('TLS1.3'),
});

export const mfaEvidenceSchema = z.strictObject({
  contractType: z.literal('MfaEvidence'),
  ...entityMetadataShape,
  status: z.enum(mfaEvidenceStatusValues),
  principalId: openPcUrnSchema,
  sessionId: openPcUrnSchema,
  method: z.literal('WEBAUTHN'),
  challengeDigest: sha256DigestSchema,
  rpIdHash: sha256DigestSchema,
  verifiedAt: rfc3339MicrosUtcSchema,
  validUntil: rfc3339MicrosUtcSchema,
  actionIntentId: actionIntentIdSchema,
});

export const recoveryCaseSchema = z.strictObject({
  contractType: z.literal('RecoveryCase'),
  ...entityMetadataShape,
  status: z.enum(recoveryCaseStatusValues),
  recoveryPrincipalId: openPcUrnSchema,
  subjectId: openPcUrnSchema,
  purposeDigest: sha256DigestSchema,
  custodianPrincipalIds: z
    .tuple([openPcUrnSchema, openPcUrnSchema])
    .refine(([first, second]) => first !== second, 'custodians must be distinct'),
  leaseExpiresAt: rfc3339MicrosUtcSchema,
  postReviewRequired: z.literal(true),
});

export const revocationRecordSchema = z.strictObject({
  contractType: z.literal('RevocationRecord'),
  ...entityMetadataShape,
  status: z.enum(revocationRecordStatusValues),
  aggregateId: openPcUrnSchema,
  priorEpoch: uint64StringSchema,
  newEpoch: uint64StringSchema,
  reasonCode: z.string().min(1),
  effectiveAt: rfc3339MicrosUtcSchema,
  evidenceDigest: sha256DigestSchema,
});

export const oidcAuthorizationSchema = z.strictObject({
  status: z.enum(['REQUESTED', 'CALLBACK_VALIDATED', 'CONSUMED']),
  flow: z.literal('AUTHORIZATION_CODE'),
  pkceMethod: z.literal('S256'),
  issuer: z.url(),
  clientId: z.string().min(1),
  redirectUri: z.url(),
  authorizationUri: z.url(),
  stateDigest: sha256DigestSchema,
  nonceDigest: sha256DigestSchema,
  codeChallenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
  expiresAt: rfc3339MicrosUtcSchema,
  traceSetId: z.literal('TS-ID-AUTHENTICATION'),
});

export type Principal = z.infer<typeof principalSchema>;
export type Session = z.infer<typeof sessionSchema>;
export type WorkloadCredential = z.infer<typeof workloadCredentialSchema>;
export type MfaEvidence = z.infer<typeof mfaEvidenceSchema>;
export type RecoveryCase = z.infer<typeof recoveryCaseSchema>;
export type RevocationRecord = z.infer<typeof revocationRecordSchema>;
export type OidcAuthorization = z.infer<typeof oidcAuthorizationSchema>;
