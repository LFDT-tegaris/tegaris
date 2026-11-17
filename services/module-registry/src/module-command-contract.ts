import { createHash } from 'node:crypto';
import { z } from 'zod';
import { sha256 } from '../../control-api/src/configuration/digest.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uint64 = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine(
    (value) => /^(0|[1-9][0-9]{0,19})$/u.test(value) && BigInt(value) <= 18446744073709551615n,
  );
export const moduleResourceRefSchema = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );

/** The mutation producer and historical approval view share one closed contract. */
export const createModuleReleaseSchema = z.strictObject({
  name: z.string().regex(/^pc\.[a-z][a-z0-9.-]{1,126}$/u),
  semanticVersion: z.string().regex(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u),
  manifestDigest: digest,
  supportProfile: z.enum(['R1', 'FUTURE_CONDITIONAL', 'EXCLUDED']),
  actionIntentId: z.literal('ACT-MODULES_CREATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});

export const moduleReleaseResponseSchema = z.strictObject({
  moduleId: moduleResourceRefSchema,
  name: z.string(),
  semanticVersion: z.string(),
  manifestDigest: digest,
  supportProfile: z.literal('R1'),
  state: z.enum(['REGISTERED', 'INSTALLED', 'ACTIVE', 'DISABLED']),
  revision: z.string().regex(/^[1-9][0-9]*$/u),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});

export const moduleLifecycleSchema = (
  action: 'ACT-MODULE_CREATE_INSTALL-V1' | 'ACT-MODULE_ACTIVATE_RESOURCE-V1',
) =>
  z.strictObject({
    actionIntentId: z.literal(action),
    actionIntentDigest: digest,
    expectedRevision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
    inputDigest: digest,
    reason: z.string().min(1).max(1024),
    targetRef: moduleResourceRefSchema,
  });

/** Module update: the target identity is owned by the path/candidate binding. */
export const disableModuleSchema = z.strictObject({
  actionIntentId: z.literal('ACT-MODULES_UPDATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  expectedRevision: uint64,
  replacementDigest: digest,
  reason: z.string().min(1).max(1024),
});

export const moduleDisableDescriptorSchema = z.strictObject({
  operation: z.literal('MOD-OP-DISABLE'),
  targetRef: moduleResourceRefSchema,
  expectedRevision: uint64,
  manifestDigest: digest,
});

export const moduleDisableDigestDomain = 'pc.control.module-disable.v1';

/** Transport intent, NOT PC-CBOR simulation/state identity. Match the existing
 * request-digest convention: UTF-8 domain + NUL, then uint32-BE byte length and
 * UTF-8 value for operation, targetRef, expectedRevision, manifestDigest, in that
 * order. Preserve the canonical uint64 decimal string without Number conversion.
 * The mutation owner recomputes this from the exact unchanged release/revision. */
export function moduleDisableReplacementDigest(input: unknown): `sha256:${string}` {
  const descriptor = moduleDisableDescriptorSchema.parse(input);
  const hash = createHash('sha256').update(`${moduleDisableDigestDomain}\0`);
  for (const value of [
    descriptor.operation,
    descriptor.targetRef,
    descriptor.expectedRevision,
    descriptor.manifestDigest,
  ]) {
    const bytes = Buffer.from(value, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return `sha256:${hash.digest('hex')}`;
}

/** Binds a lifecycle command to its exact immutable release and revision. */
export const moduleLifecycleInputDigest = (
  targetRef: string,
  expectedRevision: string,
  manifestDigest: string,
) => sha256({ targetRef, expectedRevision, manifestDigest });
