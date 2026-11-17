import { z } from 'zod';

export const digestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const uuidSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
export const openPcUrnSchema = z
  .string()
  .regex(
    /^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
export const participantUrnSchema = openPcUrnSchema;
export const resourceUrnSchema = openPcUrnSchema;
const uint64Schema = z.string().regex(/^(?:0|[1-9][0-9]{0,19})$/u);
const timestampSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u);

const action = z.object({
  actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
});
export const actionEnvelopeSchema = action;

export const semanticVersionSchema = z
  .string()
  .regex(
    /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u,
  );

export const createProviderProfileSchema = action
  .extend({
    participantId: participantUrnSchema,
    chainId: uint64Schema,
    endpointSecretRef: openPcUrnSchema,
    behaviorFingerprint: digestSchema,
  })
  .strict();

export const createIndexerProfileSchema = action
  .extend({
    participantId: participantUrnSchema,
    engine: z.enum(['CLIENT_INDEXER', 'EXTERNAL_ENGINE_ADAPTER']),
    engineVersion: semanticVersionSchema,
    methodProfileDigest: digestSchema,
  })
  .strict();

export const createProjectionPlanSchema = action
  .extend({
    indexerProfileId: resourceUrnSchema,
    planDigest: digestSchema,
    readiness: z.literal('UNKNOWN'),
  })
  .strict();

export const createRuntimeTargetSchema = action
  .extend({
    participantId: participantUrnSchema,
    desiredGenerationDigest: z.null(),
    activeGenerationDigest: z.null(),
    xdsVersionDigest: z.null(),
    observedAt: timestampSchema,
  })
  .strict();

const replacement = action
  .extend({
    expectedRevision: uint64Schema,
    replacementDigest: digestSchema,
  })
  .strict();

export const updateProviderProfileSchema = replacement;
export const updateIndexerProfileSchema = replacement;
export const updateProjectionPlanSchema = replacement;
export const updateRuntimeTargetSchema = replacement;
export const updateWorkItemSchema = replacement;

const command = action
  .extend({
    targetRef: resourceUrnSchema,
    expectedRevision: uint64Schema,
    inputDigest: digestSchema,
  })
  .strict();

export const providerQualificationSchema = command;
export const providerQuarantineSchema = command;
export const indexerAdmissionSchema = command;
export const projectionRecoverySchema = command;
export const claimWorkItemSchema = command;
export const completeWorkItemSchema = command;

export const createWorkItemSchema = action
  .extend({
    participantId: participantUrnSchema,
    kind: z.enum([
      'APPROVAL',
      'REMEDIATION',
      'DELIVERY_FAILURE',
      'FLEET_FAILURE',
      'EVIDENCE_BACKLOG',
    ]),
    assigneeRef: resourceUrnSchema.nullable(),
    resourceRef: openPcUrnSchema,
  })
  .strict();

export const scopedReadSchema = z
  .object({
    cursor: z
      .string()
      .max(2048)
      .regex(/^pc2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u)
      .optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
    filter: z
      .string()
      .regex(/^[A-Za-z][A-Za-z0-9_.-]{0,63}:(?:eq|ne|prefix):[^\r\n]{1,256}$/u)
      .optional(),
    sort: z
      .string()
      .regex(/^-?[A-Za-z][A-Za-z0-9_.-]{0,63}$/u)
      .optional(),
  })
  .strict();

const truthStateSchema = z.enum([
  'SUCCESS',
  'AUTHORIZED_EMPTY',
  'DENIED',
  'LOADING',
  'UNKNOWN',
  'UNAVAILABLE',
  'STALE',
  'REORG',
  'PARTIAL',
  'CONFLICTING',
  'DEGRADED',
  'FAILED',
  'RETRY_ELIGIBLE',
  'FAILOVER_ELIGIBLE',
  'WRITE_AMBIGUITY',
  'RECOVERY',
  'ROLLBACK',
  'RETIREMENT',
  'UNINSTALL',
  'DECOMMISSION',
]);

export const signingOperationResultSchema = z.strictObject({
  kind: z.enum([
    'NO_NEW_OBSERVATION',
    'NEW_OBSERVATION',
    'LOOKUP_UNAVAILABLE',
    'SIGNATURE_UNAVAILABLE',
    'NO_EFFECT_RETRYABLE',
    'PROVIDER_REJECTED',
    'AUTHORITY_CHANGED_BEFORE_DISPATCH',
    'AUTHORITY_RENEWED',
    'FORWARD_RECOVERY',
  ]),
  retryable: z.boolean(),
  code: z.literal('PC-INTEGRATION-5001').optional(),
  originalOperationId: uuidSchema.optional(),
  attemptId: uuidSchema.optional(),
  observationDigest: digestSchema.optional(),
});

export const operationResponseSchema = z
  .object({
    operationId: uuidSchema,
    resourceRef: resourceUrnSchema.nullable(),
    actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
    intentDigest: digestSchema,
    idempotencyKey: z
      .string()
      .min(16)
      .max(128)
      .regex(/^[A-Za-z0-9._~-]+$/u),
    state: z.enum(['ACCEPTED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'WRITE_AMBIGUITY']),
    truthState: truthStateSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    revision: uint64Schema,
    signingResult: signingOperationResultSchema.optional(),
  })
  .strict();

export const notificationResponseSchema = z.strictObject({
  notificationId: resourceUrnSchema,
  participantId: participantUrnSchema,
  severity: z.enum(['INFO', 'WARNING', 'ERROR', 'CRITICAL']),
  state: z.enum(['UNREAD', 'READ', 'ACKNOWLEDGED']),
  resourceRef: openPcUrnSchema.nullable(),
  messageKey: z.string().regex(/^[a-z][a-z0-9.]{2,127}$/u),
  revision: uint64Schema,
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
});

export const workItemResponseSchema = z
  .object({
    workItemId: resourceUrnSchema,
    participantId: participantUrnSchema,
    kind: z.enum([
      'APPROVAL',
      'REMEDIATION',
      'DELIVERY_FAILURE',
      'FLEET_FAILURE',
      'EVIDENCE_BACKLOG',
    ]),
    state: z.enum(['OPEN', 'CLAIMED', 'COMPLETED', 'CANCELLED']),
    assigneeRef: resourceUrnSchema.nullable(),
    resourceRef: openPcUrnSchema,
    revision: uint64Schema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const providerProfileResponseSchema = z
  .object({
    providerProfileId: resourceUrnSchema,
    participantId: participantUrnSchema,
    chainId: z.string().regex(/^[0-9]{1,20}$/u),
    endpointSecretRef: openPcUrnSchema,
    behaviorFingerprint: digestSchema,
    state: z.enum(['REGISTERED', 'SHADOW', 'QUALIFIED', 'ACTIVE', 'QUARANTINED', 'RETIRED']),
    authority: z.literal('NEVER_GRANTS'),
    admissionScope: z.enum(['FULL_CORPUS', 'BOUNDED_QA']).nullable().optional(),
    historicalReorgConformance: z.enum(['OBSERVED', 'NOT_TESTED']).nullable().optional(),
    revision: uint64Schema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const indexerProfileResponseSchema = z
  .object({
    indexerProfileId: resourceUrnSchema,
    participantId: participantUrnSchema,
    engine: z.enum(['CLIENT_INDEXER', 'EXTERNAL_ENGINE_ADAPTER']),
    engineVersion: semanticVersionSchema,
    methodProfileDigest: digestSchema,
    state: z.enum(['REGISTERED', 'SHADOW', 'QUALIFIED', 'ACTIVE', 'QUARANTINED', 'RETIRED']),
    authority: z.literal('CANDIDATE_ONLY'),
    revision: uint64Schema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const projectionPlanResponseSchema = z
  .object({
    projectionPlanId: resourceUrnSchema,
    indexerProfileId: resourceUrnSchema,
    planDigest: digestSchema,
    state: z.enum(['DRAFT', 'VALIDATED', 'RUNNING', 'DEGRADED', 'QUARANTINED', 'RETIRED']),
    readiness: z.enum(['UNKNOWN', 'NOT_READY', 'READY', 'STALE', 'REORG']),
    revision: uint64Schema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

/** A derived proposal input, never active state or authority. */
export const runtimeActivationCandidateResponseSchema = z.strictObject({
  targetRef: resourceUrnSchema,
  expectedRevision: uint64Schema,
  replacementDigest: digestSchema.nullable(),
});

export const runtimeTargetResponseSchema = z
  .object({
    targetId: resourceUrnSchema,
    participantId: participantUrnSchema,
    desiredGenerationDigest: digestSchema.nullable(),
    activeGenerationDigest: digestSchema.nullable(),
    xdsVersionDigest: digestSchema.nullable(),
    state: z.enum([
      'OFFLINE',
      'DISCOVERED',
      'STAGING',
      'PREPARED',
      'XDS_PENDING',
      'XDS_ACKED_NOT_ACTIVE',
      'ACTIVATING',
      'ACTIVE_MATCHED',
      'ACTIVE_MISMATCH',
      'NACKED',
      'FAILED',
      'ROLLING_BACK',
      'ROLLED_BACK',
      'QUARANTINED',
      'INCOMPATIBLE',
    ]),
    observedAt: timestampSchema,
    revision: uint64Schema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const collectionResponseSchema = <T extends z.ZodType>(item: T) =>
  z
    .object({
      items: z.array(item),
      nextCursor: z
        .string()
        .max(2048)
        .regex(/^pc2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u)
        .nullable(),
      total: uint64Schema.nullable(),
      completeness: z.enum(['COMPLETE', 'UNKNOWN']),
      authorizedEmpty: z.boolean(),
      snapshotRevision: uint64Schema,
    })
    .strict();

// Closed Fact Artifact public wire schemas, shared with the web BFF.
const factArtifactRevisionSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
export const factArtifactResponseSchema = z
  .object({
    factArtifactId: resourceUrnSchema,
    participantId: z.string().regex(/^urn:openpc:participant:/u),
    privacyDomainId: z.string().regex(/^urn:openpc:privacy-domain:/u),
    artifactDigest: digestSchema,
    authorityGeneration: digestSchema,
    state: z.enum(['CANDIDATE', 'ADMITTED', 'STALE', 'REORG', 'INVALIDATED', 'QUARANTINED']),
    sourceNeutral: z.literal(true),
    revision: factArtifactRevisionSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();
export const factArtifactOperationSchema = operationResponseSchema
  .omit({ signingResult: true })
  .extend({
    state: z.enum(['SUCCEEDED', 'FAILED']),
    truthState: z.enum(['SUCCESS', 'FAILED']),
  })
  .refine((v) => (v.state === 'SUCCEEDED') === (v.truthState === 'SUCCESS'));
export const factArtifactUpdateSchema = z
  .object({
    actionIntentId: z.literal('ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'),
    actionIntentDigest: z.literal(
      'sha256:1e0f1ff216ab9a4d35b7467f767710e05e827dc8e40943aa35d6719298c5ac2a',
    ),
    expectedRevision: factArtifactRevisionSchema,
    replacementDigest: digestSchema,
    reason: z.string().min(1).max(1024),
  })
  .strict();
