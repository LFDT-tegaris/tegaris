import { z } from 'zod';
import { digestSchema, resourceUrnSchema, uuidSchema } from '../resource-contracts.js';
import { ciglDependencyBundleSchema } from './dependency-contract.js';

const resourceId = resourceUrnSchema.refine((value) => value.startsWith('urn:openpc:resource:'));
const subjectUrn = (kind: 'role' | 'workload') =>
  resourceUrnSchema.refine((value) => value.startsWith(`urn:openpc:${kind}:`));

// Identifiers deliberately follow the existing distinct runtime resolvers.
// Neither an omitted ID nor a same-valued ID of another kind means Any.
export const ciglGrantSubjectSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('ROLE'), id: subjectUrn('role') }),
  z.strictObject({ kind: z.literal('USER'), id: uuidSchema }),
  z.strictObject({ kind: z.literal('GROUP'), id: uuidSchema }),
  z.strictObject({ kind: z.literal('WORKLOAD'), id: subjectUrn('workload') }),
  z.strictObject({ kind: z.literal('PARTICIPANT'), id: uuidSchema }),
  z.strictObject({ kind: z.literal('ANY_AUTHENTICATED') }),
]);
export const ciglGrantDefinitionSchema = z.strictObject({
  runtimeBindingId: resourceId,
  selector: z.string().regex(/^0x[0-9a-f]{8}$/u),
  subject: ciglGrantSubjectSchema,
  surface: z.enum([
    'ETH_CALL',
    'ETH_ESTIMATE_GAS',
    'PREPARE_WRITE',
    'RAW_SUBMISSION',
    'DEPLOYMENT_CONSTRUCTOR',
    'RUNTIME_WRITE_TRACE',
  ]),
  effect: z.enum(['ALLOW', 'DENY']),
});
export type CiglGrantDefinition = z.infer<typeof ciglGrantDefinitionSchema>;
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((s) => BigInt(s) <= 18446744073709551615n);
const mutation = { actionIntentDigest: digestSchema, reason: z.string().min(1).max(1024) };
export const createCiglGrantSchema = z.strictObject({
  ...mutation,
  actionIntentId: z.literal('ACT-CIGL_GRANTS_CREATE_RESOURCE-V1'),
  definition: ciglGrantDefinitionSchema,
  expectedRuntimeBindingRevision: revision,
  expectedMethodRevision: revision,
});
export const changeCiglGrantSchema = z
  .strictObject({
    ...mutation,
    actionIntentId: z.literal('ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1'),
    targetRef: resourceId,
    expectedRevision: revision,
    status: z.enum(['ACTIVE', 'DISABLED']),
    dependencyBundle: ciglDependencyBundleSchema.optional(),
  })
  .superRefine((input, context) => {
    if (input.status !== 'ACTIVE' && input.dependencyBundle !== undefined)
      context.addIssue({
        code: 'custom',
        message: 'disabled grants cannot import dependencies',
        path: ['dependencyBundle'],
      });
  });

export const ciglGrantResponseSchema = z.strictObject({
  grantId: resourceId,
  definition: ciglGrantDefinitionSchema,
  origin: z.enum(['SHARED', 'GENERATED']),
  generatedByGrantId: resourceId.nullable(),
  runtimeBindingRevision: revision,
  methodRevision: revision,
  status: z.enum(['ACTIVE', 'DISABLED']),
  revision,
  grantDigest: digestSchema,
  publicationOperationId: z.uuidv7(),
  publicationAuthorityDigest: digestSchema,
  runtimePermission: z.literal('NONE_WITHOUT_CURRENT_PROFILE'),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
