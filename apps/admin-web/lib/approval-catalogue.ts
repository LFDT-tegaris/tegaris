import { z } from 'zod';
import { transactionForms, type TransactionKind } from './transaction-workflow';

const kinds = Object.keys(transactionForms) as [TransactionKind, ...TransactionKind[]];
const count = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
export const approvalCatalogueSchema = z
  .strictObject({
    actor: z.strictObject({
      sessionId: z.uuid(),
      principalId: z.uuid(),
      participantId: z.uuid(),
      privacyDomainId: z.uuid(),
      contextEpoch: count,
    }),
    items: z
      .array(
        z.strictObject({
          approvalRequestId: z
            .string()
            .regex(
              /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
            ),
          actionIntentId: z.string().min(1).max(256),
          kinds: z.array(z.enum(kinds)).max(kinds.length),
          state: z.enum(['REQUESTED', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED']),
          relationship: z.enum(['MAKER', 'CHECKER', 'REVIEWER']),
          revision: count,
          createdAt: z.string().datetime(),
          updatedAt: z.string().datetime(),
        }),
      )
      .max(20),
    nextCursor: z.string().min(1).max(4096).nullable(),
    total: count.nullable(),
    completeness: z.enum(['COMPLETE', 'UNKNOWN']),
    authorizedEmpty: z.boolean(),
    snapshotRevision: count,
  })
  .refine(
    (page) =>
      page.authorizedEmpty === (page.items.length === 0) &&
      (!page.authorizedEmpty || page.nextCursor === null) &&
      new Set(page.items.map((item) => item.approvalRequestId)).size === page.items.length,
  );

export type ApprovalCatalogue = z.infer<typeof approvalCatalogueSchema>;
export const approvalStateLabels: Record<ApprovalCatalogue['items'][number]['state'], string> = {
  REQUESTED: 'Awaiting approval',
  APPROVED: 'Approved',
  REJECTED: 'Rejected',
  EXPIRED: 'Expired',
  CANCELLED: 'Cancelled',
};
export function approvalStateLabel(state: string): string {
  return Object.hasOwn(approvalStateLabels, state)
    ? approvalStateLabels[state as keyof typeof approvalStateLabels]
    : state;
}

export function approvalRequestLabel(kinds: readonly TransactionKind[]) {
  if (kinds.length === 1 && kinds[0]) return transactionForms[kinds[0]].label;
  if (kinds.length > 1 && kinds.every((kind) => kind.startsWith('evidence-deletion')))
    return 'Evidence removal request';
  return kinds.length ? 'Governed request' : 'Other request';
}
export function approvalTime(value: string) {
  return `${new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZone: 'UTC',
  }).format(new Date(value))} UTC`;
}
