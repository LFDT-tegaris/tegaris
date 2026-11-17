import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import {
  parseRetirementWire,
  retirementSelection,
  retirementWireBytes,
} from './store-retirement-wire.js';

const hash = z.string().regex(/^[0-9a-f]{64}$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const ordinal = z
  .string()
  .regex(/^[1-9][0-9]*$/u)
  .refine((value) => BigInt(value) <= 9223372036854775807n);
const recordRef = z.strictObject({
  candidateId: z.string().min(1).max(256),
  evidenceId: z.uuidv7(),
});
export const factRetirementPlanInput = z.strictObject({
  hostDigest: hash,
  retentionPolicyId: resourceUrnSchema,
});
export const factRetirementHosts = z.strictObject({
  items: z
    .array(
      z.strictObject({
        hostDigest: hash,
        targetId: z.string().min(1).max(256),
        store: z.literal('openpc_facts'),
      }),
    )
    .max(256),
  authority: z.literal('NONE'),
});
export const candidateRetirementPlanInput = factRetirementPlanInput;
export const candidateRetirementHosts = factRetirementHosts.extend({
  items: z
    .array(
      factRetirementHosts.shape.items.element.extend({
        store: z.literal('openpc_candidate_index'),
      }),
    )
    .max(256),
});
export const storeRetirementPlanInput = z.strictObject({
  hostDigest: hash,
  retentionPolicyId: resourceUrnSchema,
  selectionWireHex: z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/u)
    .max(2097152),
  recordRefs: z.array(recordRef).min(1).max(256),
});
const sourceBindingShape = z.strictObject({
  version: z.literal('OPENPC_STORE_RETIREMENT_SOURCE_V1'),
  selectionWireHex: storeRetirementPlanInput.shape.selectionWireHex,
  recordRefs: storeRetirementPlanInput.shape.recordRefs,
  manifest: z
    .array(
      z.strictObject({
        candidateId: z.string().min(1).max(256),
        evidenceId: z.uuidv7(),
        streamId: z.string().min(1).max(256),
        recordId: z.string().min(1).max(256),
        sequence: ordinal,
        recordDigest: digest,
        segmentId: z.uuid(),
        objectDigest: digest,
      }),
    )
    .min(1)
    .max(256),
  acknowledgements: z
    .array(
      z.strictObject({
        candidateId: z.string().min(1).max(256),
        sinkReceipts: z
          .array(
            z.strictObject({
              sinkId: z.string().min(1).max(256),
              checkpointDigest: digest,
              receiptDigest: digest,
              acknowledgedAtMicros: z.string().regex(/^[1-9][0-9]*$/u),
            }),
          )
          .max(8),
      }),
    )
    .min(1)
    .max(256),
  archiveManifestDigest: hash,
  archiveAcknowledgementDigest: hash,
  retentionNotBeforeMs: ordinal,
  lifecycleRevision: ordinal,
});
export const storeRetirementSourceBinding = sourceBindingShape.superRefine((binding, ctx) => {
  try {
    const bytes = Buffer.from(binding.selectionWireHex, 'hex');
    const selection = retirementSelection.parse(parseRetirementWire(bytes));
    if (
      !retirementWireBytes(selection).equals(bytes) ||
      selection.rows.length !== binding.recordRefs.length ||
      selection.rows.length !== binding.manifest.length ||
      selection.rows.length !== binding.acknowledgements.length ||
      binding.archiveManifestDigest !== sha256(binding.manifest).slice(7) ||
      binding.archiveAcknowledgementDigest !== sha256(binding.acknowledgements).slice(7) ||
      new Set(binding.recordRefs.map((row) => row.evidenceId)).size !== binding.recordRefs.length ||
      selection.rows.some((row, index) => {
        const ref = binding.recordRefs[index]!,
          manifest = binding.manifest[index]!,
          acks = binding.acknowledgements[index]!;
        return (
          row.candidate_id !== ref.candidateId ||
          row.candidate_id !== manifest.candidateId ||
          manifest.evidenceId !== ref.evidenceId ||
          row.candidate_id !== acks.candidateId ||
          (selection.class === 'ADMITTED_FACT' &&
            manifest.recordDigest !== `sha256:${selection.rows[index]!.signed_fact_digest}`) ||
          new Set(acks.sinkReceipts.map((receipt) => receipt.sinkId)).size !==
            acks.sinkReceipts.length
        );
      })
    )
      throw new Error('Invalid exact source binding');
  } catch {
    ctx.addIssue({ code: 'custom', message: 'Invalid exact store retirement source binding.' });
  }
});
export const admitStoreRetirement = z.strictObject({
  participantId: participantUrnSchema,
  hostDigest: hash,
  retentionPolicyId: resourceUrnSchema,
  sourceBinding: storeRetirementSourceBinding,
  previousAttemptId: resourceUrnSchema.nullable(),
  actionIntentId: z.literal('ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1'),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});
export const storeRetirementPlan = z.strictObject({
  hostDigest: hash,
  retentionPolicyId: resourceUrnSchema,
  sourceBinding: storeRetirementSourceBinding,
  nativeSourceCheck: z.literal('REQUIRED_AT_ADMISSION'),
});
export function exactStoreRetirementSourceBinding(value: unknown) {
  const binding = storeRetirementSourceBinding.parse(value);
  return {
    binding,
    digest: sha256(binding),
    selection: retirementSelection.parse(
      parseRetirementWire(Buffer.from(binding.selectionWireHex, 'hex')),
    ),
  };
}

export const storeRetirementView = z.strictObject({
  attemptId: resourceUrnSchema,
  retirementId: resourceUrnSchema,
  previousAttemptId: resourceUrnSchema.nullable(),
  participantId: participantUrnSchema,
  privacyDomainId: z.uuid(),
  hostDigest: z.string().regex(/^[0-9a-f]{64}$/u),
  admissionState: z.literal('ADMITTED'),
  operationId: z.uuidv7(),
  revision: z.literal('1'),
  admissionReceiptDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  physicalState: z.enum(['UNKNOWN', 'APPLIED', 'REJECTED_NO_EFFECT', 'CANCELLED_NO_EFFECT']),
  cancellationId: z.uuidv7().nullable(),
  outcomeDigest: z
    .string()
    .regex(/^sha256:[0-9a-f]{64}$/u)
    .nullable(),
  dispatchNotAfterMs: z.string().regex(/^[1-9][0-9]*$/u),
});
