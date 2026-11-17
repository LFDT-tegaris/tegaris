import { z } from 'zod';
import {
  assertEnvelopeScopeNarrowing,
  runtimeInvocationCapabilities,
} from '@openpc/security-kernel';
import { permissionSet } from './assignment.js';

const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u);
const nanos = z.string().regex(/^(0|[1-9][0-9]{0,19})$/u);
const dimensions = {
  participantIds: z.array(uuid).max(256),
  privacyDomainIds: z.array(uuid).max(256),
  resourceIds: z.array(id).max(256),
  dataClasses: z.array(id).max(256),
  targetProfileIds: z.array(id).max(256),
  riskClasses: z.array(z.enum(['BREAK_GLASS', 'HIGH', 'LOW', 'STANDARD'])).max(4),
};
export const envelopeScopeSchema = z
  .strictObject({
    administration: z.strictObject({
      ...dimensions,
      actionIntentIds: z.array(z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u)).max(256),
    }),
    runtime: z.strictObject({
      ...dimensions,
      capabilityIds: z.array(z.enum(runtimeInvocationCapabilities)).max(7),
    }),
    validFromNs: nanos,
    validUntilNs: nanos,
    makerCheckerRequired: z.boolean(),
    stepUpRequired: z.boolean(),
    onwardDelegationDepth: z.number().int().min(0).max(32),
  })
  .superRefine((value, ctx) => {
    try {
      assertEnvelopeScopeNarrowing(value, value);
    } catch {
      ctx.addIssue({ code: 'custom', message: 'Invalid bounded envelope scope' });
    }
  });

/** Existing parsing remains distinct from the typed alternative. A digest in
 * this legacy body is never evidence of typed grantability or signing trust. */
export const legacyEnvelopeCreate = permissionSet.extend({
  envelopeId: z.uuid(),
  semanticDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});
/** Desired scope/intent only. Parent, authority, epochs, evidence, signer and
 * resulting digest are derived by the governed owner, never request fields. */
export const typedEnvelopeCreate = z.strictObject({
  schema: z.literal('pc.identity.authority-envelope-proposal'),
  schemaVersion: z.literal(1),
  // Existing public resource references encode newly created UUIDv7 identities.
  envelopeId: uuid.refine((value) => value[14] === '7', 'New envelope IDs must be UUIDv7'),
  issuance: z.enum(['PLATFORM_ROOT', 'CHILD']),
  // Explicit root replacement handoff; this never admits future runtime scope.
  platformScopeReplacementId: z.uuidv7().optional(),
  usable: envelopeScopeSchema,
  grantable: envelopeScopeSchema,
});
export type TypedEnvelopeCreate = z.infer<typeof typedEnvelopeCreate>;
export const envelopeCreate = z.union([legacyEnvelopeCreate, typedEnvelopeCreate]);
export const typedEnvelopeCreateCandidate = typedEnvelopeCreate
  .extend({
    id: uuid,
    participantId: uuid,
    state: z.literal('DRAFT'),
  })
  .refine((value) => value.id === value.envelopeId, 'Envelope identity mismatch');
export type TypedEnvelopeCreateCandidate = z.infer<typeof typedEnvelopeCreateCandidate>;
export const envelopeActivationCandidate = z.strictObject({ envelopeId: uuid });
export const envelopeRevocationCandidate = z.strictObject({
  envelopeId: uuid,
  reason: z.string().trim().min(10).max(1024),
});
