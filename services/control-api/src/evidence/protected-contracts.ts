import { z } from 'zod';
import {
  participantUrnSchema,
  resourceUrnSchema,
  operationResponseSchema,
} from '../configuration/resource-contracts.js';
import { digest, sequence } from './segment.js';

const timestamp = z.iso.datetime({ precision: 6 });
const action = z.strictObject({
  actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});
/** Historical proof of an Identity commit; never a current authorization grant. */
export const protectedProofSource = z.strictObject({
  evidenceId: resourceUrnSchema,
  occurrenceId: z.uuidv7(),
  operationId: z.uuidv7(),
  sourceReceiptDigest: digest,
  proofDigest: digest,
  assertionDigest: digest,
  signatureDigest: digest,
  signerKeyDigest: digest,
  occurredAt: timestamp,
  materialType: z.literal('IDENTITY_SIGNED_AUTHORIZATION_ASSERTION'),
  evidenceClass: z.literal('AUTHENTICATION'),
  sourceFormat: z.literal('IDENTITY_RUNTIME_ASSERTION_3002_2_13'),
  occurrenceIntegrity: z.literal('CONTROL_DATABASE_IMMUTABLE'),
  proofIntegrity: z.literal('IDENTITY_COSE_ED25519'),
  finality: z.literal('NOT_APPLICABLE'),
  authorityEffect: z.literal('NONE'),
});
export const retainProtectedProof = action.extend({
  participantId: participantUrnSchema,
  source: protectedProofSource,
  purpose: z.string().trim().min(1).max(256),
  caseReference: z.string().trim().min(1).max(256),
  retainUntil: timestamp,
});
export const protectedObjectBinding = z.strictObject({
  objectRef: resourceUrnSchema,
  objectVersion: z.literal('1'),
  objectDigest: digest,
  source: protectedProofSource,
});
export const requestProtectedAccess = action.extend({
  participantId: participantUrnSchema,
  object: protectedObjectBinding,
  purpose: z.string().trim().min(1).max(256),
  caseReference: z.string().trim().min(1).max(256),
  recipientPrincipalId: z.uuidv7(),
  expiresAt: timestamp,
});
export const consumeProtectedAccess = action.extend({
  targetRef: resourceUrnSchema,
  expectedRevision: z.literal('1'),
  object: protectedObjectBinding,
  purpose: requestProtectedAccess.shape.purpose,
  caseReference: requestProtectedAccess.shape.caseReference,
  recipientPrincipalId: z.uuidv7(),
  expiresAt: timestamp,
});
export const protectedObjectView = protectedObjectBinding.extend({
  participantId: participantUrnSchema,
  privacyDomainId: z.uuid(),
  purpose: retainProtectedProof.shape.purpose,
  caseReference: retainProtectedProof.shape.caseReference,
  retainUntil: timestamp,
  creationOperationId: z.uuidv7(),
  createdAt: timestamp,
  revision: z.literal('1'),
  updatedAt: timestamp,
});
export const protectedAccessView = z.strictObject({
  accessRef: resourceUrnSchema,
  participantId: participantUrnSchema,
  privacyDomainId: z.uuid(),
  object: protectedObjectBinding,
  purpose: requestProtectedAccess.shape.purpose,
  caseReference: requestProtectedAccess.shape.caseReference,
  recipientPrincipalId: z.uuidv7(),
  expiresAt: timestamp,
  state: z.enum(['AVAILABLE', 'CONSUMED', 'EXPIRED']),
  creationOperationId: z.uuidv7(),
  consumptionOperationId: z.uuidv7().nullable(),
  revision: sequence,
  createdAt: timestamp,
  updatedAt: timestamp,
});
/** Delivered only on the first committed consumption, never in operation persistence. */
export const protectedDisclosure = z.strictObject({
  version: z.literal('OPENPC_PROTECTED_IDENTITY_PROOF_V1'),
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  source: protectedProofSource,
  assertionBase64: z.string().min(4).max(87384),
  coseSign1Base64: z.string().min(4).max(87384),
});
export const protectedConsumptionResponse = z.strictObject({
  operation: operationResponseSchema,
  disclosure: protectedDisclosure.nullable(),
});
