import { z } from 'zod';

export const openPcUrnSchema = z
  .string()
  .regex(
    /^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
export const uint64StringSchema = z.string().regex(/^(0|[1-9][0-9]{0,19})$/u);
export const rfc3339MicrosUtcSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u);
export const sha256DigestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const evmAddressSchema = z.string().regex(/^0x[0-9a-f]{40}$/u);
export const traceSetIdSchema = z.string().regex(/^TS-ID-[A-Z-]+$/u);

export const entityMetadataShape = {
  id: openPcUrnSchema,
  version: uint64StringSchema,
  createdAt: rfc3339MicrosUtcSchema,
  updatedAt: rfc3339MicrosUtcSchema,
  traceSetId: traceSetIdSchema,
};

export function uniqueStringsSchema() {
  return z
    .array(z.string())
    .refine((values) => new Set(values).size === values.length, 'values must be unique');
}
