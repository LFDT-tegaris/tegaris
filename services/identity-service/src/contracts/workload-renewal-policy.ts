import { createHash } from 'node:crypto';
import { z } from 'zod';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  workloadRenewalPolicyOperations,
  workloadRenewalRoutineOperation,
} from '../../../../packages/security-kernel/src/workload-renewal-operations.js';
import { sha256DigestSchema } from './primitives.js';

const counter = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const instant = z.iso.datetime({ precision: 3 });
const uuid = z.uuidv7().regex(/^[0-9a-f-]+$/u);
const workload = z
  .string()
  .regex(
    /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );

/** Approved delivery/attestation ceilings only. No role, action, permission,
 * browser session, recovery lease or caller-selected approval state belongs
 * in a renewal policy. Actual current business parents remain separate. */
export const workloadRenewalPolicyDefinitionSchema = z
  .strictObject({
    version: z.literal(1),
    participantId: uuid,
    privacyDomainId: uuid,
    policyId: uuid,
    principalId: uuid,
    workloadId: workload,
    issuerProfileDigest: sha256DigestSchema,
    providerQualificationDigest: sha256DigestSchema,
    attestationProfileDigest: sha256DigestSchema,
    managedAttestorScopeDigest: sha256DigestSchema,
    maximumInstances: z.number().int().min(1).max(1024),
    maximumEnrollmentsPerMinute: z.number().int().min(1).max(1024),
    certificateLifetimeSeconds: z.number().int().min(1).max(86400),
    recoveryReserveSeconds: z.number().int().min(1).max(86400),
    maximumOverlapSeconds: z.number().int().min(1).max(300),
    validFrom: instant,
    validUntil: instant,
  })
  .superRefine((value, context) => {
    const targetAge = Math.min(value.certificateLifetimeSeconds / 2, 43200);
    const lead = value.certificateLifetimeSeconds - targetAge;
    if (!(
      value.maximumOverlapSeconds < value.recoveryReserveSeconds &&
      value.recoveryReserveSeconds < lead &&
      lead < value.certificateLifetimeSeconds
    ))
      context.addIssue({
        code: 'custom',
        message: 'coherent renewal, reserve and overlap bounds required',
      });
    if (Date.parse(value.validUntil) <= Date.parse(value.validFrom))
      context.addIssue({ code: 'custom', message: 'finite policy interval required' });
  });
export type WorkloadRenewalPolicyDefinition = z.infer<typeof workloadRenewalPolicyDefinitionSchema>;

export const workloadRenewalPolicyProposalSchema = z.strictObject({
  requestId: uuid,
  expectedRevision: counter,
  definition: workloadRenewalPolicyDefinitionSchema,
  reason: z
    .string()
    .min(1)
    .max(1024)
    .refine((value) => value.normalize('NFC') === value),
});
export const workloadRenewalPolicyStopSchema = z.strictObject({
  requestId: uuid,
  expectedRevision: counter.refine((value) => value !== '0'),
  reason: z
    .string()
    .min(1)
    .max(1024)
    .refine((value) => value.normalize('NFC') === value),
});
export const workloadRenewalPolicyRecordSchema = z.strictObject({
  policyId: uuid,
  revision: counter.refine((value) => value !== '0'),
  state: z.enum(['ACTIVE', 'SUSPENDED', 'REVOKED']),
  definition: workloadRenewalPolicyDefinitionSchema,
  definitionDigest: sha256DigestSchema,
  governanceOperationId: uuid,
  runtimePermission: z.literal('NONE'),
});

/** Renewal-policy catalog; original identityOperations remains immutable. */
export const workloadRenewalExtensionOperations = Object.freeze([
  ...workloadRenewalPolicyOperations,
  workloadRenewalRoutineOperation,
]);

export function workloadRenewalPolicyDefinitionBytes(input: WorkloadRenewalPolicyDefinition) {
  return Buffer.from(canonicalDefinitionJson(workloadRenewalPolicyDefinitionSchema.parse(input)));
}
export function workloadRenewalPolicyDefinitionDigest(input: WorkloadRenewalPolicyDefinition) {
  return `sha256:${createHash('sha256').update(workloadRenewalPolicyDefinitionBytes(input)).digest('hex')}` as const;
}

/** Compute once from the authoritative certificate interval and persist the
 * result. Restart/process/browser time is never an input. Jitter is earlier
 * than the target by at most 10%, stable for this exact family and policy. */
export function workloadRenewalSchedule(
  policy: WorkloadRenewalPolicyDefinition,
  familyId: string,
  certificateNotBefore: string,
  certificateNotAfter: string,
) {
  const definition = workloadRenewalPolicyDefinitionSchema.parse(policy);
  z.uuidv7().parse(familyId);
  const from = Date.parse(instant.parse(certificateNotBefore));
  const until = Date.parse(instant.parse(certificateNotAfter));
  const lifetime = until - from;
  const targetAge = Math.min(lifetime / 2, 43200000);
  const reserve = definition.recoveryReserveSeconds * 1000;
  const overlap = definition.maximumOverlapSeconds * 1000;
  if (!(
    lifetime > 0 &&
    lifetime <= definition.certificateLifetimeSeconds * 1000 &&
    overlap < reserve &&
    reserve < lifetime - targetAge &&
    lifetime - targetAge < lifetime
  ))
    throw new Error('Incoherent authoritative certificate renewal interval');
  const seed = createHash('sha256')
    .update('pc.identity.workload-renewal.schedule.v1\0')
    .update(familyId)
    .update('\0')
    .update(workloadRenewalPolicyDefinitionDigest(definition))
    .digest();
  const jitter = Math.floor((seed.readUInt32BE(0) / 0xffffffff) * targetAge * 0.1);
  return Object.freeze({
    nextRenewAt: new Date(from + Math.floor(targetAge) - jitter).toISOString(),
    renewalDeadline: new Date(until - reserve).toISOString(),
  });
}
