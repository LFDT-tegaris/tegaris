import { z } from 'zod';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';

const resource = resourceUrnSchema.refine((v) => v.startsWith('urn:openpc:resource:'));
const amount = z.string().regex(/^[1-9][0-9]{0,77}$/u);

/** Independent protected Native Value permission. The maker names a real
 * wallet/executor and exact reviewed limits; all authority fields are derived. */
export const createNativeValueAuthorizationSchema = z
  .strictObject({
    actionIntentId: z.literal('ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1'),
    actionIntentDigest: digestSchema,
    reason: z.string().min(1).max(1024),
    walletBindingId: resource,
    executionWorkloadId: z
      .string()
      .regex(
        /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      )
      .optional(),
    chainId: z
      .string()
      .regex(/^[1-9][0-9]{0,19}$/u)
      .refine((v) => BigInt(v) <= 18446744073709551615n),
    networkId: z.string().regex(/^[A-Za-z][A-Za-z0-9_.:-]{0,47}$/u),
    genesisDigest: digestSchema,
    amountMode: z.enum(['EXACT', 'MAXIMUM']),
    maxAmountWei: amount,
    validUntil: z.iso.datetime({ precision: 3 }),
  })
  .refine((input) => `${input.chainId}:${input.networkId}:${input.genesisDigest}`.length <= 128, {
    message: 'chain environment identifier exceeds the Native Value limit',
  });
export type CreateNativeValueAuthorization = z.infer<typeof createNativeValueAuthorizationSchema>;

export const nativeValueAuthorizationResponseSchema = z.strictObject({
  nativeValueAuthorizationId: resource,
  walletBindingId: resource,
  state: z.enum(['UNUSED', 'CONSUMED', 'EXPIRED', 'INVALIDATED']),
  revision: z.literal('1'),
  runtimePermission: z.literal('NONE'),
  // Current authorization document, emitted losslessly by the Rust owner. Its used flag
  // reflects durable consumption, while the issued digest retains provenance.
  authorizationDocument: z
    .string()
    .regex(/^0x(?:[0-9a-f]{2})+$/u)
    .max(8194),
  authorizationDigest: digestSchema,
  issuedAuthorizationDigest: digestSchema,
  creationOperationId: z.uuid(),
  createdAt: z.iso.datetime(),
  validUntil: z.iso.datetime(),
});
