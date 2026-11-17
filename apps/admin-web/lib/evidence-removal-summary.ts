import { z } from 'zod';
import type { TransactionKind } from './transaction-workflow';

const uuid = z.uuid();
const resource = z
  .string()
  .regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u)
  .refine((value) => uuid.safeParse(value.slice(-36)).success);
const participant = z
  .string()
  .regex(/^urn:openpc:participant:[0-9a-f-]{36}$/u)
  .refine((value) => uuid.safeParse(value.slice(-36)).success);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const bytes = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const dataClasses = {
  AUDIT_EVIDENCE: 'Stored evidence',
  SEARCH_PROJECTION: 'Search index',
  NORMALIZED_JSON_PROJECTION: 'Normalized record',
  RAW_SOURCE_BODY: 'Protected source body',
  RUNTIME_ARTIFACT: 'Runtime artifact',
} as const;
const removalKinds = new Set<TransactionKind>([
  'evidence-deletion',
  'evidence-deletion-batch',
  'evidence-deletion-continuation',
  'evidence-deletion-search',
  'evidence-deletion-normalized',
  'evidence-deletion-projection-continuation',
  'evidence-deletion-raw',
  'evidence-deletion-raw-continuation',
  'evidence-deletion-runtime',
]);

// The BFF validates the complete native result. This projection prevents an
// unrelated or incomplete record from acquiring a physical-deletion label.
const removal = z.object({
  deletionJobId: resource,
  participantId: participant,
  state: z.literal('SUCCEEDED'),
  revision: z.literal('1'),
  deletedCount: z.literal('1'),
  deletedBytes: bytes,
  retainedAliasCount: z.literal('0'),
  externalAttemptState: z.literal('NOT_STARTED'),
  receiptDigest: digest,
  beforeDigest: digest,
  afterDigest: digest,
  completedAt: z.iso.datetime({ precision: 6 }),
  selection: z
    .object({
      participantId: participant,
      privacyDomainId: uuid,
      dataClass: z.enum([
        'AUDIT_EVIDENCE',
        'SEARCH_PROJECTION',
        'NORMALIZED_JSON_PROJECTION',
        'RAW_SOURCE_BODY',
        'RUNTIME_ARTIFACT',
      ]),
      batchIndex: z.number().int().min(0).max(127).optional(),
      targets: z.array(z.unknown()).min(1).max(128).optional(),
    })
    .refine((value) =>
      value.batchIndex === undefined
        ? value.targets === undefined
        : value.targets !== undefined && value.batchIndex < value.targets.length,
    ),
});

export function evidenceRemovalSummary(
  kind: TransactionKind | undefined,
  value: unknown,
  context: { participantId: string; privacyDomainId: string; resourceRef: string | undefined },
) {
  if (!kind || !removalKinds.has(kind)) return undefined;
  const parsed = removal.safeParse(value);
  if (!parsed.success) return undefined;
  const result = parsed.data;
  if (
    result.deletionJobId !== context.resourceRef ||
    result.participantId !== `urn:openpc:participant:${context.participantId}` ||
    result.selection.participantId !== result.participantId ||
    result.selection.privacyDomainId !== context.privacyDomainId
  )
    return undefined;
  return {
    label: dataClasses[result.selection.dataClass],
    bytes: result.deletedBytes,
    completedAt: result.completedAt,
    receiptDigest: result.receiptDigest,
    ...(result.selection.batchIndex !== undefined && result.selection.targets
      ? { batch: result.selection.batchIndex + 1, batches: result.selection.targets.length }
      : {}),
  };
}
