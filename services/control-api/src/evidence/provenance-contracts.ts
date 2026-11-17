import { z } from 'zod';
import { rpcProvenance } from './rpc-provenance-contract.js';
import { factProvenance } from './fact-provenance-contract.js';
import { participantUrnSchema, resourceUrnSchema } from '../configuration/resource-contracts.js';
import { digest, evidenceClass, sequence, evidenceChainId } from './segment.js';

const reference = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
const operationId = z.string().regex(/^urn:openpc:operation:[0-9a-f-]{36}$/u);
const historicalOnly = {
  authority: z.literal('NONE'),
  currentAuthority: z.literal('NOT_ESTABLISHED'),
  chainFinality: z.literal('NOT_APPLICABLE'),
};
const authentication = z.strictObject({
  ...historicalOnly,
  integrity: z.literal('CONTROL_DATABASE_IMMUTABLE'),
  occurrenceId: z.uuidv7(),
  operationId,
  sourceId: z.uuidv7(),
  principalId: z.uuid(),
  method: z.enum(['OIDC_CODE_PKCE_S256', 'WEBAUTHN_ASSERTION', 'TLS13_MTLS']),
  contextMode: z.enum(['PLATFORM', 'PARTICIPANT', 'WORKLOAD']),
  occurredAt: z.iso.datetime({ precision: 6 }),
  credentialDigest: digest,
  proofDigest: digest,
  contextBindingDigest: digest,
});
const businessState = z.strictObject({
  existence: z.number().int().min(0).max(2),
  revision: sequence,
  stateDigest: digest,
});
const business = z.strictObject({
  ...historicalOnly,
  integrity: z.literal('VERIFIED_PROFILE_COSE'),
  meaning: z.literal('COMMITTED_BUSINESS_TRANSITION'),
  providerEffect: z.literal('NOT_ESTABLISHED'),
  currentObjectState: z.literal('NOT_QUERIED'),
  receiptId: z.uuidv7(),
  operationId,
  idempotencyRecordId: z.uuidv7(),
  profileId: reference,
  profileVersion: sequence,
  profileDigest: digest,
  actionIntentId: reference,
  catalogOperationId: reference,
  aggregateType: reference,
  aggregateId: z.uuid(),
  candidateDigest: digest,
  requestDigest: digest,
  actorKeyDigest: digest,
  authorityDigest: digest,
  signerId: digest,
  signerTrustDigest: digest,
  payloadDigest: digest,
  recordedAt: z.iso.datetime({ precision: 6 }),
  before: businessState,
  after: businessState,
  authorizationReferences: z
    .array(
      z.strictObject({
        kind: z.number().int().min(1).max(5),
        evidenceId: reference,
        evidenceDigest: digest,
      }),
    )
    .max(32),
  outboxReferences: z
    .array(
      z.strictObject({
        eventId: z.uuidv7(),
        eventType: reference,
        sequence,
        correlationId: z.uuidv7(),
        causationId: z.uuidv7().nullable(),
        payloadDigest: digest,
      }),
    )
    .max(16),
});
const rejection = z.strictObject({
  ...historicalOnly,
  integrity: z.literal('VERIFIED_PURPOSE_SIGNATURE'),
  meaning: z.literal('TERMINAL_PRE_HANDOFF_REJECTION'),
  sourceVersion: z.literal('1'),
  operationId,
  attemptId: z.uuidv7(),
  observedAt: z.iso.datetime({ offset: true }),
  state: z.literal('REJECTED'),
  truthState: z.literal('DENIED'),
  transactionHash: z.string().regex(/^0x[0-9a-f]{64}$/u),
  candidateDigest: digest,
  authorizationEvidenceDigest: digest,
  execution: z.literal('NO_HANDOFF'),
});
const observation = z.strictObject({
  sourceVersion: sequence,
  receiptDigest: digest,
  observedAt: z.iso.datetime({ offset: true }),
  state: z.enum([
    'ATTEMPT_STARTED',
    'ACCEPTED',
    'WRITE_AMBIGUITY',
    'CONFIRMED',
    'REJECTED',
    'FAILED',
    'REORG',
  ]),
  truthState: z.enum([
    'UNKNOWN',
    'WRITE_AMBIGUITY',
    'SUCCESS',
    'DENIED',
    'CONFLICTING',
    'FAILED',
    'UNAVAILABLE',
    'REORG',
  ]),
  journalEvidenceDigest: digest,
  finality: z.enum(['FINALIZED', 'REORG', 'INVALIDATED', 'NOT_ESTABLISHED']),
  occurrence: z
    .strictObject({
      occurrenceId: reference,
      occurrenceDigest: digest,
      blockHash: digest,
      blockNumber: sequence,
      reorgStatus: z.literal('CANONICAL'),
    })
    .nullable(),
  invalidation: z
    .strictObject({
      occurrenceId: reference,
      occurrenceDigest: digest,
      observationDigest: digest,
      reason: z.enum(['REORG', 'CODE_IDENTITY_MISMATCH']),
    })
    .nullable(),
});

const deployment = z.strictObject({
  integrity: z.literal('VERIFIED_PURPOSE_SIGNATURE'),
  authority: z.literal('OBSERVATION_ONLY'),
  operationId: z.string().regex(/^urn:openpc:operation:[0-9a-f-]{36}$/u),
  attemptId: z.uuidv7(),
  deploymentIntentId: resourceUrnSchema,
  targetRuntimeId: resourceUrnSchema,
  executionPrincipalId: z.uuid(),
  workloadId: reference,
  intentDigest: digest,
  preparationDigest: digest,
  chainId: evidenceChainId,
  genesisDigest: digest,
  transactionHash: z.string().regex(/^0x[0-9a-f]{64}$/u),
  historical: observation,
  latestRetained: observation,
  historicalIsLatest: z.boolean(),
  currentChainTruth: z.literal('NOT_QUERIED'),
  history: z.strictObject({
    coverage: z.literal('RETAINED_SNAPSHOTS_ONLY'),
    firstVersion: sequence,
    lastVersion: sequence,
    retainedCount: sequence,
    missingVersionsBetweenSnapshots: sequence,
    journalCompleteness: z.literal('NOT_ESTABLISHED'),
  }),
});

// Only the immutable selected observation belongs to the removable operator
// projection. Latest source history is resolved from its signed owner at read.
export const deploymentProvenanceProjection = deployment.omit({
  latestRetained: true,
  historicalIsLatest: true,
  currentChainTruth: true,
  history: true,
});

/** Minimized references only. Neither this view nor its catalogue membership
 * grants raw receipt access, current chain authority or deletion eligibility. */
export const evidenceProvenanceView = z
  .strictObject({
    evidenceId: resourceUrnSchema,
    participantId: participantUrnSchema,
    privacyDomainId: z.uuid(),
    evidenceClass,
    recordId: reference,
    recordDigest: digest,
    sourceFormat: reference,
    status: z.enum([
      'VERIFIED_DEPLOYMENT_OBSERVATION',
      'VERIFIED_AUTHENTICATION_OCCURRENCE',
      'VERIFIED_BUSINESS_TRANSITION',
      'VERIFIED_TERMINAL_REJECTION',
      'VERIFIED_RPC_CUSTODY_PROJECTION',
      'VERIFIED_FACT_CUSTODY_PROJECTION',
      'SOURCE_RECONCILIATION_REQUIRED',
      'PROJECTION_RETIRED',
      'SOURCE_NOT_SUPPORTED',
    ]),
    deployment: deployment.nullable(),
    authentication: authentication.nullable().optional(),
    business: business.nullable().optional(),
    rejection: rejection.nullable().optional(),
    rpc: rpcProvenance.nullable().optional(),
    fact: factProvenance.nullable().optional(),
    custody: z.strictObject({
      streamId: reference,
      sequence,
      segmentId: z.uuid(),
      checkpoints: z
        .array(
          z.strictObject({
            sinkId: reference,
            throughSequence: sequence,
            objectDigest: digest,
            versionId: digest,
            receiptDigest: digest,
            checkpointDigest: digest,
            previousCheckpointDigest: digest.nullable(),
            assurance: z.literal('LOCAL_FSYNC_READBACK'),
            acknowledgedAt: z.iso.datetime({ offset: true }),
          }),
        )
        .max(16),
      checkpointState: z.enum(['RECORDED', 'NONE_RECORDED']),
      archiveAvailability: z.literal('NOT_RECHECKED'),
    }),
  })
  .refine(
    (value) => (value.status === 'VERIFIED_DEPLOYMENT_OBSERVATION') === (value.deployment !== null),
  )
  .refine(
    (value) =>
      (value.status === 'VERIFIED_AUTHENTICATION_OCCURRENCE') === Boolean(value.authentication) &&
      (value.status === 'VERIFIED_BUSINESS_TRANSITION') === Boolean(value.business) &&
      (value.status === 'VERIFIED_TERMINAL_REJECTION') === Boolean(value.rejection) &&
      (value.status === 'VERIFIED_RPC_CUSTODY_PROJECTION') === Boolean(value.rpc) &&
      (value.status === 'VERIFIED_FACT_CUSTODY_PROJECTION') === Boolean(value.fact),
  );
export type EvidenceProvenance = z.infer<typeof evidenceProvenanceView>;
