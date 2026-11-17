import { z } from 'zod';
import { encodeCanonicalCbor, type CanonicalCborValue } from '@openpc/security-kernel';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import { digest, evidenceScope, sequence, evidenceChainId } from './segment.js';
import { sha256 } from '../configuration/digest.js';

const resource = resourceUrnSchema.regex(/^urn:openpc:resource:/u);
const factProfile = resourceUrnSchema.regex(/^urn:openpc:fact-profile:/u);

/** A null upper sequence preserves every future match in the named stream. */
export const evidenceHoldSelector = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('PARTICIPANT') }),
  z.strictObject({ type: z.literal('PRIVACY_DOMAIN') }),
  z.strictObject({ type: z.literal('PROJECTION'), projectionId: resource }),
  z.strictObject({
    type: z.literal('FACT_TYPE_KEY'),
    factType: z.enum(['CONTRACT_STATE_CALL', 'RELATIONSHIP', 'EXTERNAL_DECISION']),
    factProfileId: factProfile,
    factKeyDigest: digest.nullable(),
  }),
  z
    .strictObject({
      type: z.literal('BLOCK_RANGE'),
      chainId: evidenceChainId,
      genesisDigest: digest,
      fromBlock: sequence,
      throughBlock: sequence.nullable(),
    })
    .refine(
      (value) =>
        value.throughBlock === null || BigInt(value.throughBlock) >= BigInt(value.fromBlock),
    ),
  z.strictObject({
    type: z.literal('GENERATION'),
    generation: z.discriminatedUnion('kind', [
      z.strictObject({ kind: z.literal('RUNTIME_CONFIGURATION'), generationId: resource }),
      z.strictObject({
        kind: z.literal('CANONICAL_FACT'),
        factProfileId: factProfile,
        canonicalGeneration: sequence.refine((value) => BigInt(value) > 0n),
      }),
    ]),
  }),
  z
    .strictObject({
      type: z.literal('SEQUENCE_RANGE'),
      streamId: evidenceScope.shape.streamId,
      fromSequence: sequence,
      throughSequence: sequence.nullable(),
    })
    .refine(
      (value) =>
        BigInt(value.fromSequence) > 0n &&
        (value.throughSequence === null ||
          BigInt(value.throughSequence) >= BigInt(value.fromSequence)),
    ),
  z.strictObject({ type: z.literal('DIGEST'), recordDigest: digest }),
]);
export type EvidenceHoldSelector = z.infer<typeof evidenceHoldSelector>;
const action = z.strictObject({
  actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});
export const createEvidenceHold = action
  .extend({
    participantId: participantUrnSchema,
    holdKind: z.enum(['LEGAL', 'REGULATORY', 'INCIDENT']),
    selector: evidenceHoldSelector,
  })
  .refine(
    (value) =>
      (value.selector.type === 'PARTICIPANT') ===
      (value.actionIntentId === 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1'),
  );
export const releaseEvidenceHold = action.extend({
  targetRef: resourceUrnSchema,
  expectedRevision: sequence,
});
const timestamp = z.iso.datetime({ precision: 6 });
export const evidenceHoldView = z.strictObject({
  holdId: resourceUrnSchema,
  participantId: participantUrnSchema,
  holdKind: createEvidenceHold.shape.holdKind,
  selector: evidenceHoldSelector,
  selectorDigest: digest,
  governancePrivacyDomainId: z.uuid().optional(),
  coveragePrivacyDomainId: z.uuid().optional(),
  state: z.enum(['ACTIVE', 'RELEASED']),
  revision: sequence,
  // An active rule blocks deletion even while sink coverage is incomplete.
  coverage: z.enum(['PENDING', 'VERIFIED', 'UNAVAILABLE']),
  creationOperationId: z.uuidv7(),
  releaseOperationId: z.uuidv7().nullable(),
  // Historical development rows may predate typed business receipts.
  creationReceiptDigest: digest.nullable(),
  releaseReceiptDigest: digest.nullable(),
  effectiveAt: timestamp,
  createdAt: timestamp,
  updatedAt: timestamp,
});

/** PC-CBOR-1 selector binding; current context is server-derived, never wildcard input. */
export function encodeEvidenceHoldSelector(
  scope: { participantId: string; privacyDomainId: string },
  input: EvidenceHoldSelector,
) {
  const participant = z.uuid().parse(scope.participantId),
    privacy = z.uuid().parse(scope.privacyDomainId),
    selector = evidenceHoldSelector.parse(input);
  const fields = new Map<number, CanonicalCborValue>([
    [0, 'pc.evidence.hold-selector.v1'],
    [1, Buffer.from(participant.replaceAll('-', ''), 'hex')],
    [2, Buffer.from(privacy.replaceAll('-', ''), 'hex')],
    [3, selector.type],
  ]);
  if (selector.type === 'SEQUENCE_RANGE') {
    fields.set(4, selector.streamId);
    fields.set(5, BigInt(selector.fromSequence));
    fields.set(6, selector.throughSequence === null ? 0 : 1);
    if (selector.throughSequence !== null) fields.set(7, BigInt(selector.throughSequence));
  } else if (selector.type === 'DIGEST')
    fields.set(4, Buffer.from(selector.recordDigest.slice(7), 'hex'));
  else if (selector.type === 'PROJECTION')
    fields.set(4, Buffer.from(selector.projectionId.slice(-36).replaceAll('-', ''), 'hex'));
  else if (selector.type === 'FACT_TYPE_KEY') {
    fields.set(4, selector.factType);
    fields.set(5, selector.factProfileId);
    fields.set(6, selector.factKeyDigest === null ? 0 : 1);
    if (selector.factKeyDigest !== null)
      fields.set(7, Buffer.from(selector.factKeyDigest.slice(7), 'hex'));
  } else if (selector.type === 'BLOCK_RANGE') {
    fields.set(4, selector.chainId);
    fields.set(5, Buffer.from(selector.genesisDigest.slice(7), 'hex'));
    fields.set(6, BigInt(selector.fromBlock));
    fields.set(7, selector.throughBlock === null ? 0 : 1);
    if (selector.throughBlock !== null) fields.set(8, BigInt(selector.throughBlock));
  } else if (selector.type === 'GENERATION') {
    fields.set(4, selector.generation.kind);
    if (selector.generation.kind === 'RUNTIME_CONFIGURATION')
      fields.set(
        5,
        Buffer.from(selector.generation.generationId.slice(-36).replaceAll('-', ''), 'hex'),
      );
    else {
      fields.set(5, selector.generation.factProfileId);
      fields.set(6, BigInt(selector.generation.canonicalGeneration));
    }
  }
  const bytes = encodeCanonicalCbor(fields);
  return { selector, bytes, digest: sha256(bytes) };
}
