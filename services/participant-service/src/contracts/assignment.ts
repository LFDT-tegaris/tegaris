import { z } from 'zod';
import { runtimeInvocationCapabilities } from '@openpc/security-kernel';

const uuid = z.uuid();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const permissionSet = z.strictObject({
  privacyDomainIds: z.array(z.string().min(1)).min(1),
  actionIntentIds: z.array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u)).max(256),
  capabilityIds: z
    .array(z.enum(runtimeInvocationCapabilities))
    .max(7)
    .refine((values) => new Set(values).size === values.length, 'duplicate runtime capability')
    .optional(),
  resourceIds: z.array(z.string().min(1)).min(1),
  riskClasses: z.array(z.string().min(1)).min(1),
  validFrom: z.coerce.date(),
  validUntil: z.coerce.date(),
  makerCheckerRequired: z.boolean(),
  stepUpRequired: z.boolean(),
  onwardDelegationDepth: z.number().int().min(0).max(32),
});
export const assignmentCreate = permissionSet.extend({
  assignmentId: uuid,
  groupId: uuid.optional(),
  principalId: uuid,
  roleId: z
    .string()
    .max(256)
    .regex(
      /^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    )
    .optional(),
  authorityEnvelopeId: uuid,
  scopeDigest: digest,
});

/** Exact candidate produced by the public assignment command. No identity secrets. */
export const assignmentCreateCandidate = assignmentCreate
  .extend({
    id: uuid,
    participantId: uuid,
    state: z.literal('ACTIVE'),
    delegationEpoch: z.literal('0'),
    validFrom: z.iso.datetime(),
    validUntil: z.iso.datetime(),
  })
  .refine((value) => value.id === value.assignmentId, 'assignment identity mismatch');
