import { z } from 'zod';

const uint256 = z.string().regex(/^0x[0-9a-f]{64}$/u);
const uint64 = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .pipe(z.string().refine((value) => BigInt(value) <= 18446744073709551615n));

/** RPC-CONTRACT-001 reference ceilings; a binding can only narrow them. */
export const transactionPolicySchema = z
  .object({
    version: z.literal(1),
    allowedTransactionTypes: z
      .array(z.union([z.literal(0), z.literal(1), z.literal(2)]))
      .min(1)
      .max(3)
      .refine((types) => types.every((kind, index) => index === 0 || types[index - 1]! < kind)),
    maximumValue: uint256,
    maximumGasLimit: uint64,
    maximumFeePerGas: uint256,
    maximumPriorityFeePerGas: uint256,
    maximumRawTransactionBytes: z.number().int().min(1).max(131072),
    maximumCalldataBytes: z.number().int().min(4).max(32768),
    maximumAccessListAddresses: z.number().int().min(0).max(128),
    maximumAccessListStorageKeys: z.number().int().min(0).max(1024),
  })
  .strict()
  .refine((policy) => policy.maximumPriorityFeePerGas <= policy.maximumFeePerGas);

export type TransactionPolicy = z.infer<typeof transactionPolicySchema>;
