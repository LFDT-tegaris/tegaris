import { z } from 'zod';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';

export const runtimeTargetProfileIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u);

export const createRuntimeTargetProfileBindingSchema = z.strictObject({
  actionIntentId: z.literal('ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
  runtimeTargetRef: resourceUrnSchema.refine((value) => value.startsWith('urn:openpc:resource:')),
  targetRevision: z
    .string()
    .regex(/^[1-9][0-9]{0,18}$/u)
    .refine((value) => BigInt(value) <= 9223372036854775807n),
  targetProfileId: runtimeTargetProfileIdSchema,
});
export type CreateRuntimeTargetProfileBinding = z.infer<
  typeof createRuntimeTargetProfileBindingSchema
>;

export const runtimeTargetProfileBindingResponseSchema = z.strictObject({
  bindingRef: resourceUrnSchema,
  targetRef: resourceUrnSchema,
  targetProfileId: runtimeTargetProfileIdSchema,
  bindingDigest: digestSchema,
  publicationOperationRef: resourceUrnSchema,
  revision: z.literal('1'),
  runtimePermission: z.literal('NONE_WITHOUT_MATCHING_ENVELOPE'),
  createdAt: z.iso.datetime(),
});
