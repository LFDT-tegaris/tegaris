import { factAdmissionDelivery } from './fact-delivery-contract.js';
import { z } from 'zod';
import { resourceUrnSchema } from '../configuration/resource-contracts.js';
import { digest, evidenceChainId, sequence } from './segment.js';
const positive = sequence.regex(/^[1-9][0-9]{0,19}$/u);
const resource = resourceUrnSchema.regex(/^urn:openpc:resource:/u);
const factId = resourceUrnSchema.regex(/^urn:openpc:fact:/u);
export const FACT_EVIDENCE_FORMAT = 'OPENPC_CANONICAL_FACT_V1';
export const factLineage = z.strictObject({
  factId,
  factDigest: digest,
  factType: z.enum(['CONTRACT_STATE_CALL', 'RELATIONSHIP', 'EXTERNAL_DECISION']),
  factProfileId: resourceUrnSchema.regex(/^urn:openpc:fact-profile:/u),
  factKeyDigest: digest,
  canonicalGeneration: positive,
  projectionId: resource,
  chainId: evidenceChainId,
  genesisDigest: digest,
  blockNumber: sequence,
  blockHash: digest,
  predecessorDigest: digest.nullable(),
  relationshipPredecessorDigest: digest.nullable(),
  reorgReplacementOf: factId.nullable(),
});
export const factEvidenceRecord = z.strictObject({
  candidateId: z.uuidv7(),
  sourceSequence: positive,
  receiptDigest: digest,
  receiptBase64: z.string().min(1).max(180000),
  admittedAt: z.iso.datetime({ precision: 6 }),
  lineage: factLineage,
  admissionDelivery: factAdmissionDelivery.optional(),
});
export const factProvenance = factEvidenceRecord
  .omit({ receiptBase64: true, admissionDelivery: true })
  .extend({
    integrity: z.literal('FACT_COSE_VERIFIED_AT_CUSTODY'),
    authority: z.literal('NONE'),
    currentReadiness: z.literal('NOT_ESTABLISHED'),
    sourceProfileId: z.uuidv7(),
    verificationKeyId: digest,
    verificationKeyDigest: digest,
  });
export type FactProvenance = z.infer<typeof factProvenance>;

export const factEvidenceBatch = z.strictObject({
  identity: z.literal('OPENPC_FACT_EVIDENCE_SOURCE_V1'),
  verificationKeyDigest: digest,
  sourceProfileId: z.uuidv7(),
  checkpointSequence: sequence,
  checkpointState: z.enum(['COMPLETE', 'GAP_BLOCKED', 'REORG_FENCED', 'QUARANTINED']),
  records: z.array(factEvidenceRecord).max(8),
});
