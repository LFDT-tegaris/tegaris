import { z } from 'zod';

const reference = z
  .string()
  .refine(
    (value) =>
      value.startsWith('urn:openpc:resource:') &&
      z.uuid().safeParse(value.slice('urn:openpc:resource:'.length)).success,
  );
const record = {
  id: reference,
  label: z.string(),
  revision: z.string().regex(/^[1-9][0-9]*$/u),
  createdAt: z.string(),
};
const page = {
  actor: z.strictObject({
    sessionId: z.uuid(),
    principalId: z.uuid(),
    participantId: z.uuid(),
    privacyDomainId: z.uuid(),
    contextEpoch: z.string().min(1),
  }),
  nextCursor: z
    .string()
    .max(2048)
    .regex(/^pc2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u)
    .nullable(),
  total: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  completeness: z.literal('COMPLETE'),
  authorizedEmpty: z.boolean(),
  snapshotRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
};
export const contractCatalogueKind = z.enum(['contracts', 'bindings', 'methods', 'abis']);
export type ContractCatalogueKind = z.infer<typeof contractCatalogueKind>;
export const contractCataloguePage = z
  .discriminatedUnion('kind', [
    z.strictObject({
      ...page,
      kind: z.literal('contracts'),
      items: z.array(z.strictObject({ ...record, logicalName: z.string() })).max(25),
    }),
    z.strictObject({
      ...page,
      kind: z.literal('bindings'),
      items: z
        .array(
          z.strictObject({
            ...record,
            logicalContractId: reference,
            abiArtifactId: reference,
            abiDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
            contractAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/u),
            chainId: z.string(),
            networkId: z.string(),
            state: z.enum(['BOUND', 'QUARANTINED', 'RETIRED']),
          }),
        )
        .max(25),
    }),
    z.strictObject({
      ...page,
      kind: z.literal('methods'),
      items: z
        .array(
          z.strictObject({
            ...record,
            runtimeBindingId: reference,
            abiArtifactId: reference,
            selector: z.string().regex(/^0x[0-9a-f]{8}$/u),
            effect: z.enum(['READ', 'WRITE']),
            state: z.enum(['PREPARED', 'ACTIVE', 'RETIRED', 'QUARANTINED']),
            approvalRequirement: z.enum(['NONE', 'SINGLE', 'MAKER_CHECKER']),
            mfaRequirement: z.enum(['NONE', 'WEBAUTHN']),
          }),
        )
        .max(25),
    }),
    z.strictObject({
      ...page,
      kind: z.literal('abis'),
      items: z
        .array(
          z.strictObject({
            ...record,
            abiDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
            source: z.string(),
            functions: z.number().int().nonnegative(),
          }),
        )
        .max(25),
    }),
  ])
  .refine(
    (value) =>
      value.authorizedEmpty === (value.items.length === 0) &&
      new Set(value.items.map((item) => item.id)).size === value.items.length &&
      (value.nextCursor === null || value.items.length === 25),
  );
export type ContractCataloguePage = z.infer<typeof contractCataloguePage>;
export type ContractCatalogueSelection = {
  [Kind in ContractCatalogueKind]: {
    kind: Kind;
    item: Extract<ContractCataloguePage, { kind: Kind }>['items'][number];
  };
}[ContractCatalogueKind];
export type ContractCatalogueMethod = Extract<
  ContractCataloguePage,
  { kind: 'methods' }
>['items'][number];
