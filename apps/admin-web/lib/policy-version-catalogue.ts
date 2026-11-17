import { z } from 'zod';
import { policyVersionResponseSchema } from '../../../services/module-registry/src/policy-version-contract';

export const policyVersionActorSchema = z.strictObject({
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  principalId: z.uuid(),
  sessionId: z.uuid(),
  contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
});
const count = z.string().regex(/^(?:0|[1-9][0-9]{0,19})$/u);
export const policyVersionCatalogueSchema = z
  .strictObject({
    actor: policyVersionActorSchema,
    policySetId: z.string(),
    items: z.array(policyVersionResponseSchema).max(20),
    nextCursor: z.string().min(1).max(2048).nullable(),
    total: count.nullable(),
    completeness: z.enum(['COMPLETE', 'UNKNOWN']),
    authorizedEmpty: z.boolean(),
    snapshotRevision: count,
  })
  .refine(
    (page) =>
      page.items.every((item) => item.policySetId === page.policySetId) &&
      new Set(page.items.map((item) => item.policyVersionId)).size === page.items.length &&
      page.authorizedEmpty === (page.items.length === 0) &&
      (!page.authorizedEmpty || page.nextCursor === null) &&
      (page.total === null || BigInt(page.total) >= BigInt(page.items.length)),
  );
export const policyVersionSelectionSchema = z.strictObject({
  actor: policyVersionActorSchema,
  version: policyVersionResponseSchema,
});
export type PolicyVersionCatalogue = z.infer<typeof policyVersionCatalogueSchema>;
export type PolicyVersionSelection = z.infer<typeof policyVersionSelectionSchema>;

export function policyVersionTime(value: string) {
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
