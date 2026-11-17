import { z } from 'zod';

import { quotedSha256EtagPattern, rfc3339MicrosUtcPattern, uuidV7Pattern } from './contracts';

export const localReplacementDocument = '{"factType":"qualification","state":"ADMITTED"}';

export const localFactAction = Object.freeze({
  actionIntentId: 'ACT-UI_FACT_SOURCE_PROJECTION_BRIDGE_QUALIFY_ADMIT-V1',
  actionIntentDigest: 'sha256:2da81e172788f4fc9d713b9579c40d5fc1f0a8ea29dc79a4b6d2f386913afc3b',
  operationId: 'commandUiFactSourceProjectionBridgeQualifyAdmit',
  riskClass: 'HIGH',
  stepUp: 'FRESH_WEBAUTHN_MAX_5M',
  idempotencyKey: 'local-runtime-qualify-admit-v1',
  targetRef: 'urn:openpc:ui-process:6ac3e161-8930-7329-b132-946785fe269b',
  resourceRef: 'urn:openpc:resource:6ac3e161-8930-7329-b132-946785fe269b',
  participantRef: 'urn:openpc:participant:018f0000-0000-7000-8000-000000000101',
  privacyDomainRef: 'urn:openpc:privacy-domain:018f0000-0000-7000-8000-000000000201',
  inputDigest: 'sha256:0809216c5dda13e8be4bf7577579ca507bd9a6d700f32ff768b86e6e47d024d8',
  downstreamActionIntentId: 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',
  downstreamActionIntentDigest:
    'sha256:1e0f1ff216ab9a4d35b7467f767710e05e827dc8e40943aa35d6719298c5ac2a',
} as const);

export const localFactCommandSchema = z
  .object({
    actionIntentId: z.literal(localFactAction.actionIntentId),
    actionIntentDigest: z.literal(localFactAction.actionIntentDigest),
    expectedRevision: z.literal('1'),
    inputDigest: z.literal(localFactAction.inputDigest),
    reason: z.string().min(1).max(1024),
    targetRef: z.literal(localFactAction.targetRef),
  })
  .strict();

export const localOperationSchema = z
  .object({
    actionIntentId: z.literal(localFactAction.downstreamActionIntentId),
    createdAt: z.string().regex(rfc3339MicrosUtcPattern),
    idempotencyKey: z.literal(localFactAction.idempotencyKey),
    intentDigest: z.literal(localFactAction.downstreamActionIntentDigest),
    operationId: z.string().regex(uuidV7Pattern),
    resourceRef: z.literal(localFactAction.resourceRef),
    revision: z.literal('1'),
    state: z.literal('SUCCEEDED'),
    truthState: z.literal('SUCCESS'),
    updatedAt: z.string().regex(rfc3339MicrosUtcPattern),
  })
  .strict();

export const localSessionBootstrapSchema = z
  .object({
    csrfToken: z.string().min(32).max(256),
    etag: z.string().regex(quotedSha256EtagPattern),
    idempotencyKey: z
      .string()
      .min(16)
      .max(128)
      .regex(/^[A-Za-z0-9._~-]+$/),
    locale: z.string().min(1),
    timeZone: z.string().min(1),
    density: z.string().min(1),
    theme: z.string().min(1),
  })
  .strict();

export const localOwnerResultSchema = z
  .object({
    outcome: z.enum(['ADMITTED_NOT_READY', 'REPLACEMENT_FINALIZED', 'IDEMPOTENT_REPLAY']),
    operation: localOperationSchema,
    etag: z.string().regex(quotedSha256EtagPattern),
    requestId: z.string().regex(uuidV7Pattern),
    correlationId: z.string().regex(uuidV7Pattern),
  })
  .strict();

export const localSnapshotHeadersSchema = z
  .object({
    etag: z.string().regex(quotedSha256EtagPattern),
    apiVersion: z.literal('1'),
    rateLimit: z.number().int().nonnegative().safe(),
    rateRemaining: z.number().int().nonnegative().safe(),
    rateReset: z.number().int().nonnegative().safe(),
    requestId: z.string().regex(uuidV7Pattern),
    correlationId: z.string().regex(uuidV7Pattern),
  })
  .strict()
  .refine((value) => value.rateRemaining <= value.rateLimit, 'rate remaining exceeds limit');

export const localOwnerReadSchema = z
  .object({
    factCount: z.number().int().nonnegative().safe(),
    latestCandidateId: z.string().min(1).max(256).nullable(),
    latestState: z.literal('ADMITTED').nullable(),
    observedAtMs: z.number().int().nonnegative().safe().nullable(),
    resourceRef: z.literal(localFactAction.resourceRef).nullable(),
    etag: z.string().regex(quotedSha256EtagPattern),
    requestId: z.string().regex(uuidV7Pattern),
    correlationId: z.string().regex(uuidV7Pattern),
  })
  .strict()
  .superRefine((value, context) => {
    const projectionFields = [
      value.latestCandidateId,
      value.latestState,
      value.observedAtMs,
      value.resourceRef,
    ];
    const validEmpty = value.factCount === 0 && projectionFields.every((field) => field === null);
    const validPopulated = value.factCount > 0 && projectionFields.every((field) => field !== null);
    if (!validEmpty && !validPopulated) {
      context.addIssue({
        code: 'custom',
        message: 'fact projection fields must match factCount',
      });
    }
  });

export type LocalOperation = z.infer<typeof localOperationSchema>;
