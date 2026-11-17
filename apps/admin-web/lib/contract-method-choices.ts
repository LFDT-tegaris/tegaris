import { z } from 'zod';

const reference = z
  .string()
  .regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u)
  .refine((value) => z.uuid().safeParse(value.slice(-36)).success);

export const contractMethodChoicesSchema = z
  .strictObject({
    actor: z.strictObject({
      sessionId: z.uuid(),
      principalId: z.uuid(),
      participantId: z.uuid(),
      privacyDomainId: z.uuid(),
      contextEpoch: z.string().min(1),
    }),
    runtimeBindingId: reference,
    abiArtifactId: reference,
    abiDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    methods: z
      .array(
        z.strictObject({
          signature: z.string().min(1),
          selector: z.string().regex(/^0x[0-9a-f]{8}$/u),
          effect: z.enum(['READ', 'WRITE']),
        }),
      )
      .max(4096),
  })
  .refine(
    (value) =>
      new Set(value.methods.map((method) => method.signature)).size === value.methods.length &&
      new Set(value.methods.map((method) => method.selector)).size === value.methods.length,
  );

export type ContractMethodChoice = z.infer<typeof contractMethodChoicesSchema>['methods'][number];
