import { createHash } from 'node:crypto';
import { z } from 'zod';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { businessProviderObservationSchema } from './business-signing-provider.js';
import { identityEnvelopeRotationObservationSchema } from './identity-envelope-rotation-provider.js';
import {
  retainHandoverPreparationObservation,
  type HandoverProviderBinding,
} from './workload-signing-handover-provider.js';
import {
  retainHandoverPossessionObservation,
  type HandoverPossessionGeneration,
  type HandoverProviderAttempt,
} from './workload-signing-handover-possession.js';

const via = z.enum(['DISPATCH', 'LOOKUP']);
/** External truth only. None of these results admits a key or authorizes a retry. */
export const handoverProviderResultSchema = z.discriminatedUnion('state', [
  z.strictObject({
    state: z.literal('OBSERVED'),
    via,
    observation: z.union([
      businessProviderObservationSchema,
      identityEnvelopeRotationObservationSchema,
    ]),
  }),
  z.strictObject({
    state: z.literal('UNKNOWN'),
    via,
    reason: z.literal('TRANSPORT_OR_PROTOCOL_UNKNOWN'),
  }),
  z.strictObject({
    state: z.literal('UNOBSERVED'),
    via: z.literal('LOOKUP'),
    reason: z.enum(['ABSENT', 'NOT_FOUND', 'UNKNOWN']),
  }),
]);
export type HandoverProviderResult = z.infer<typeof handoverProviderResultSchema>;

export function validateHandoverProviderResult(
  binding: HandoverProviderBinding,
  attempt: HandoverProviderAttempt,
  input: HandoverProviderResult,
  generation?: HandoverPossessionGeneration,
): HandoverProviderResult {
  const result = handoverProviderResultSchema.parse(input);
  if (result.state !== 'OBSERVED') return result;
  const retained =
    'stage' in attempt
      ? (() => {
          const key = generation?.keys.find(
            (key) => key.binding.replacement.oldFingerprint === attempt.predecessorFingerprint,
          );
          if (
            !generation ||
            !key ||
            canonicalDefinitionJson(key.binding) !== canonicalDefinitionJson(binding)
          )
            throw new Error('Original possession generation is unavailable');
          return retainHandoverPossessionObservation(generation, attempt, result.observation);
        })()
      : retainHandoverPreparationObservation(binding, attempt, result.observation);
  return { ...result, observation: retained.observation };
}

export function handoverProviderResultBytes(input: HandoverProviderResult): Buffer {
  return Buffer.from(canonicalDefinitionJson(handoverProviderResultSchema.parse(input)));
}

export function handoverProviderResultDigest(input: HandoverProviderResult): Buffer {
  return createHash('sha256')
    .update('pc.identity.workload-signing-handover.provider-result.v1\0')
    .update(handoverProviderResultBytes(input))
    .digest();
}

/** A later transport failure cannot erase a confirmed response. A provider
 * changing its immutable answer makes the entire attempt conflicting. */
export function summarizeHandoverProviderResults(results: readonly HandoverProviderResult[]) {
  let first: Extract<HandoverProviderResult, { state: 'OBSERVED' }> | undefined;
  let conflicting = false;
  for (const input of results) {
    const result = handoverProviderResultSchema.parse(input);
    if (result.state !== 'OBSERVED') continue;
    if (!first) first = result;
    else if (
      canonicalDefinitionJson(first.observation) !== canonicalDefinitionJson(result.observation)
    )
      conflicting = true;
  }
  if (conflicting) return { state: 'CONFLICTING' as const, firstObservation: first!.observation };
  if (first) return { state: 'OBSERVED' as const, firstObservation: first.observation };
  return { state: 'UNKNOWN' as const, firstObservation: null };
}
