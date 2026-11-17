import { z } from 'zod';
import type {
  WorkItem,
  WorkItemPage,
  Operation,
} from '../../../generated/typescript/openapi/types.gen';
import {
  createWorkItemSchema,
  updateWorkItemSchema,
  claimWorkItemSchema,
  collectionResponseSchema,
  digestSchema,
  openPcUrnSchema,
  operationResponseSchema,
  uuidSchema,
  workItemResponseSchema,
} from '../../../services/control-api/src/configuration/resource-contracts';

// Browser-safe projections of public owners. These identifiers describe actions,
// not a caller's authority to perform them.
export const workItemEndpoint = '/api/v1/ui/work-item-workbench';
export const workItemActions = {
  CREATE: 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
  UPDATE: 'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
  CLAIM: 'ACT-OPERATIONS_UPDATE_CLAIM-V1',
  COMPLETE: 'ACT-OPERATIONS_UPDATE_COMPLETE-V1',
} as const;
const exact = (value: string) => value === value.trim();
export const workItemId = uuidSchema.refine(exact);
export const workItemRef = openPcUrnSchema.refine(
  (value) => exact(value) && value.startsWith('urn:openpc:resource:'),
);
const revision = claimWorkItemSchema.shape.expectedRevision.refine(
  (value) =>
    exact(value) && /^[1-9][0-9]{0,19}$/u.test(value) && BigInt(value) <= 18446744073709551615n,
);
const etag = z
  .string()
  .regex(/^"sha256:[0-9a-f]{64}"$/u)
  .refine(exact);
export const workItemBinding = z.strictObject({
  actorKey: digestSchema.refine(exact),
  actor: z.strictObject({
    participantId: workItemId,
    privacyDomainId: workItemId,
    principalRef: workItemRef,
  }),
});
export const workItemCreateFields = createWorkItemSchema
  .pick({ kind: true, resourceRef: true, assigneeRef: true, reason: true })
  .extend({ resourceRef: openPcUrnSchema.refine(exact), assigneeRef: workItemRef.nullable() })
  .strict();
const request = { actorKey: workItemBinding.shape.actorKey, requestKey: z.uuid() };
const selected = {
  ...request,
  workItemRef,
  expectedRevision: revision,
  etag,
  reason: claimWorkItemSchema.shape.reason,
};
export const workItemCommand = z.discriminatedUnion('command', [
  z.strictObject({ ...request, command: z.literal('CREATE'), ...workItemCreateFields.shape }),
  z.strictObject({
    ...selected,
    command: z.literal('UPDATE'),
    replacementDigest: updateWorkItemSchema.shape.replacementDigest.refine(exact),
  }),
  z.strictObject({ ...selected, command: z.literal('CLAIM') }),
  z.strictObject({ ...selected, command: z.literal('COMPLETE') }),
]);
// Narrow public projections before they enter either server or browser state.
const unsigned = claimWorkItemSchema.shape.expectedRevision.refine(
  (value) =>
    exact(value) && /^(0|[1-9][0-9]{0,19})$/u.test(value) && BigInt(value) <= 18446744073709551615n,
);
export const workItemRecord = workItemResponseSchema
  .extend({
    workItemId: workItemRef,
    assigneeRef: workItemRef.nullable(),
    resourceRef: openPcUrnSchema.refine(exact),
    revision,
  })
  .strict();
export const workItemPage = collectionResponseSchema(workItemRecord)
  .extend({
    items: z.array(workItemRecord).max(50),
    total: unsigned.nullable(),
    snapshotRevision: unsigned,
    nextCursor: collectionResponseSchema(workItemRecord)
      .shape.nextCursor.unwrap()
      .refine(exact)
      .nullable(),
  })
  .strict()
  .refine(
    (page) =>
      (page.total === null ||
        (unsigned.safeParse(page.total).success &&
          BigInt(page.total) >= BigInt(page.items.length))) &&
      (!page.authorizedEmpty ||
        (page.items.length === 0 &&
          page.total === '0' &&
          page.completeness === 'COMPLETE' &&
          page.nextCursor === null)),
  );
export const workItemOperation = operationResponseSchema
  .omit({ signingResult: true })
  .extend({
    operationId: workItemId,
    resourceRef: workItemRef,
    revision: unsigned,
  })
  .strict();
export const workItemQuery = z.discriminatedUnion('view', [
  z.strictObject({
    view: z.literal('LIST'),
    cursor: collectionResponseSchema(workItemRecord)
      .shape.nextCursor.unwrap()
      .refine(exact)
      .optional(),
    limit: z.enum(['10', '25', '50']).default('25'),
    filter: z
      .string()
      .max(512)
      .regex(/^(state|kind|assigneeRef|resourceRef):(eq|ne|prefix):[^\r\n]+(?![\s\S])/u)
      .optional(),
    sort: z.enum(['updatedAt', '-updatedAt']).default('-updatedAt'),
  }),
  z.strictObject({ view: z.literal('DETAIL'), actorKey: request.actorKey, workItemRef }),
  z.strictObject({
    view: z.literal('OPERATION'),
    actorKey: request.actorKey,
    operationId: workItemId,
  }),
]);
export const workItemView = z.discriminatedUnion('kind', [
  workItemBinding.extend({ kind: z.literal('LIST'), page: workItemPage }).strict(),
  workItemBinding.extend({ kind: z.literal('DETAIL'), workItem: workItemRecord, etag }).strict(),
  workItemBinding.extend({ kind: z.literal('OPERATION'), operation: workItemOperation }).strict(),
]);
export type WorkItemCommand = z.infer<typeof workItemCommand>;
export type WorkItemView = z.infer<typeof workItemView>;
export type WorkItemBinding = z.infer<typeof workItemBinding>;
export type { WorkItem, WorkItemPage, Operation };
// Actor-bound recovery hints only. Never credentials or proof of authority.
export const workItemPending = z.strictObject({
  request: workItemCommand,
  operationId: workItemId.optional(),
  uncertain: z.boolean(),
});
export type WorkItemPending = z.infer<typeof workItemPending>;
