import { z } from 'zod';

const ref = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const count = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const time = z.iso.datetime({ precision: 6 });
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const protectedActorSchema = z.strictObject({
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  principalId: z.uuid(),
  sessionId: z.uuid(),
  contextEpoch: count,
});
const common = {
  purpose: z.string().min(1).max(256),
  caseReference: z.string().min(1).max(256),
  createdAt: time,
  updatedAt: time,
};
export const protectedObjectSummarySchema = z.strictObject({
  ...common,
  objectRef: ref,
  objectVersion: z.literal('1'),
  retainUntil: time,
});
const accessSummarySchema = z.strictObject({
  ...common,
  accessRef: ref,
  objectRef: ref,
  objectVersion: z.literal('1'),
  state: z.enum(['AVAILABLE', 'CONSUMED', 'EXPIRED']),
  expiresAt: time,
  recipientPrincipalId: z.uuid(),
});
const page = {
  actorKey: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  actor: protectedActorSchema,
  nextCursor: z.string().min(1).max(2048).nullable(),
  total: count.nullable(),
  completeness: z.enum(['COMPLETE', 'UNKNOWN']),
  authorizedEmpty: z.boolean(),
  snapshotRevision: count,
};
export const protectedCatalogueSchema = z
  .discriminatedUnion('catalogue', [
    z.strictObject({
      ...page,
      catalogue: z.literal('objects'),
      items: z.array(protectedObjectSummarySchema).max(20),
    }),
    z.strictObject({
      ...page,
      catalogue: z.literal('access'),
      items: z.array(accessSummarySchema).max(20),
    }),
  ])
  .refine(
    (value) =>
      value.authorizedEmpty === (value.items.length === 0) &&
      (!value.authorizedEmpty || value.nextCursor === null) &&
      (value.total === null || BigInt(value.total) >= BigInt(value.items.length)) &&
      new Set(value.items.map((item) => ('accessRef' in item ? item.accessRef : item.objectRef)))
        .size === value.items.length,
  );
export const protectedObjectSelectionSchema = z.strictObject({
  actorKey: page.actorKey,
  actor: protectedActorSchema,
  object: protectedObjectSummarySchema,
});
// Native schemas are validated in the BFF. The browser keeps only delivery
// metadata; signed source material is not needed to select or reconcile access.
export const protectedAccessSelectionSchema = z.object({
  actorKey: page.actorKey,
  actor: protectedActorSchema,
  accessDigest: digest,
  access: z.object({
    ...common,
    accessRef: ref,
    participantId: z.string().regex(/^urn:openpc:participant:[0-9a-f-]{36}$/u),
    privacyDomainId: z.uuid(),
    purpose: common.purpose,
    caseReference: common.caseReference,
    state: z.enum(['AVAILABLE', 'CONSUMED', 'EXPIRED']),
    expiresAt: time,
    recipientPrincipalId: z.uuid(),
    revision: count,
    consumptionOperationId: z.uuid().nullable(),
    object: z.object({ objectRef: ref, objectVersion: z.literal('1'), objectDigest: digest }),
  }),
});
export type ProtectedCatalogue = z.infer<typeof protectedCatalogueSchema>;
export type ProtectedObjectSelection = z.infer<typeof protectedObjectSelectionSchema>;
export type ProtectedAccessSelection = z.infer<typeof protectedAccessSelectionSchema>;

export function protectedProofTime(value: string) {
  return `${new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' }).format(new Date(value))} UTC`;
}
export function protectedUtcInput(value: string) {
  if (!value) return '';
  const date = new Date(`${value}Z`);
  return Number.isFinite(date.getTime())
    ? date
        .toISOString()
        .replace(/([0-9]{3})Z$/u, (_match, milliseconds: string) => `${milliseconds}000Z`)
    : '';
}
