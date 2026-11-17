import { z } from 'zod';
import { encodeCanonicalCbor, type CanonicalCborValue } from '@openpc/security-kernel';
import {
  participantUrnSchema,
  resourceUrnSchema,
  semanticVersionSchema,
} from '../configuration/resource-contracts.js';
import { sha256 } from '../configuration/digest.js';
import { digest, sequence } from './segment.js';

// Each retention data class has its own policy; classes do not inherit policies.
export const retentionDataClass = z.enum([
  'RAW_SOURCE_BODY',
  'NORMALIZED_JSON_PROJECTION',
  'SEARCH_PROJECTION',
  'RUNTIME_ARTIFACT',
  'ADMITTED_FACT',
  'CANDIDATE_PROJECTION',
  'AUDIT_EVIDENCE',
  'NOTIFICATION_PAYLOAD',
  'OUTBOX_INBOX',
  'IDENTITY_RECORD',
]);
export const retentionDeletionMode = z.enum([
  'ROW_DELETE',
  'PROJECTION_DELETE',
  'IDENTIFIER_ALIAS',
  'CRYPTO_SHRED',
]);
// Exact PostgreSQL duration_ms, without JavaScript floating-point coercion.
export const retentionDuration = sequence.refine((value) => BigInt(value) <= 9223372036854775807n);
export const retentionPolicyDefinition = z.strictObject({
  dataClass: retentionDataClass,
  policyVersion: semanticVersionSchema.max(128),
  retentionPeriodMs: retentionDuration,
  localGraceMs: retentionDuration,
  sinkQuorum: z.number().int().min(0).max(8),
  deletionMode: retentionDeletionMode,
  makerCheckerRequired: z.boolean(),
});
const action = z.strictObject({
  actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});
export const activateRetentionPolicy = action.extend({
  participantId: participantUrnSchema,
  predecessorPolicyId: resourceUrnSchema.nullable(),
  policy: retentionPolicyDefinition,
});
export const retireRetentionPolicy = action.extend({
  targetRef: resourceUrnSchema,
  expectedRevision: z.literal('1'),
});
export const retentionPolicyView = retentionPolicyDefinition.extend({
  retentionPolicyId: resourceUrnSchema,
  participantId: participantUrnSchema,
  predecessorPolicyId: resourceUrnSchema.nullable(),
  policyDigest: digest,
  state: z.enum(['ACTIVE', 'RETIRED']),
  revision: sequence,
  activationOperationId: z.uuidv7(),
  retirementOperationId: z.uuidv7().nullable(),
  activationReceiptDigest: digest,
  retirementReceiptDigest: digest.nullable(),
  activeFrom: z.iso.datetime({ precision: 6 }),
  activeUntil: z.iso.datetime({ precision: 6 }).nullable(),
  createdAt: z.iso.datetime({ precision: 6 }),
  updatedAt: z.iso.datetime({ precision: 6 }),
});
export function encodeRetentionPolicy(
  scope: { participantId: string; privacyDomainId: string },
  input: z.infer<typeof retentionPolicyDefinition>,
) {
  const policy = retentionPolicyDefinition.parse(input);
  const bytes = encodeCanonicalCbor(
    new Map<number, CanonicalCborValue>([
      [0, 'pc.evidence.retention-policy.v1'],
      [1, Buffer.from(z.uuid().parse(scope.participantId).replaceAll('-', ''), 'hex')],
      [2, Buffer.from(z.uuid().parse(scope.privacyDomainId).replaceAll('-', ''), 'hex')],
      [3, policy.dataClass],
      [4, policy.policyVersion],
      [5, BigInt(policy.retentionPeriodMs)],
      [6, BigInt(policy.localGraceMs)],
      [7, policy.sinkQuorum],
      [8, policy.deletionMode],
      [9, policy.makerCheckerRequired ? 1 : 0],
    ]),
  );
  return { policy, bytes, digest: sha256(bytes) };
}
