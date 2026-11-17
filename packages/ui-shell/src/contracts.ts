import { z } from 'zod';

import { actionIntents, truthStates, type ActionIntent, type TruthState } from './registry';

export const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const openPcUrnPattern =
  /^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const sha256DigestPattern = /^sha256:[0-9a-f]{64}$/;
export const quotedSha256EtagPattern = /^"sha256:[0-9a-f]{64}"$/;
export const rfc3339MicrosUtcPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

export const authorizedActionSchema = z
  .object({
    actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/),
    actionIntentDigest: z.string().regex(sha256DigestPattern),
    operationId: z.string().regex(/^[a-z][A-Za-z0-9]+$/),
    method: z.enum(['POST', 'PUT', 'PATCH', 'DELETE']),
    path: z.string().regex(/^\/api\/v1\//),
    riskClass: z.enum(['LOW', 'STANDARD', 'HIGH', 'BREAK_GLASS']),
    stepUp: z.enum(['NONE', 'FRESH_WEBAUTHN_MAX_5M', 'BREAK_GLASS_PROFILE']),
    idempotency: z.enum(['KEY_UNTIL_TERMINAL', 'KEY_24H_MINIMUM', 'NEVER_REPLAY_EFFECT']),
    etagRequired: z.boolean(),
  })
  .strict();

export type AuthorizedAction = z.infer<typeof authorizedActionSchema>;

export const processSnapshotSchema = z
  .object({
    snapshotId: z.string().regex(uuidV7Pattern),
    routeId: z.string().regex(/^ROUTE-[A-Z0-9-]+$/),
    processDomainId: z.string().regex(/^[A-Z][A-Z0-9_]+$/),
    contextDigest: z.string().regex(sha256DigestPattern),
    authorityGeneration: z.string().regex(/^(0|[1-9][0-9]{0,19})$/),
    policyGeneration: z.string().regex(/^(0|[1-9][0-9]{0,19})$/),
    truthState: z.enum(truthStates),
    scope: z
      .object({
        plane: z.enum(['PLATFORM', 'PARTICIPANT', 'WORKLOAD', 'SEPARATE_PRODUCT']),
        participantId: z.string().regex(openPcUrnPattern).nullable(),
        privacyDomainId: z.string().regex(openPcUrnPattern).nullable(),
      })
      .strict(),
    observedAt: z.string().regex(rfc3339MicrosUtcPattern),
    freshness: z
      .object({
        observedAt: z.string().regex(rfc3339MicrosUtcPattern),
        state: z.enum(['CURRENT', 'STALE', 'UNKNOWN']),
      })
      .strict(),
    completeness: z.enum(['COMPLETE', 'PARTIAL', 'UNKNOWN']),
    items: z
      .array(
        z
          .object({
            resourceRef: z.string().regex(openPcUrnPattern),
            truthState: z.enum(truthStates),
            scopeDigest: z.string().regex(sha256DigestPattern),
            observedAt: z.string().regex(rfc3339MicrosUtcPattern),
          })
          .strict(),
      )
      .max(100),
    authorizedActions: z.array(authorizedActionSchema).max(14),
    evidenceRefs: z
      .array(z.string().regex(openPcUrnPattern))
      .max(20)
      .refine((values) => new Set(values).size === values.length, 'evidenceRefs must be unique'),
  })
  .strict();

export type ProcessSnapshot = z.infer<typeof processSnapshotSchema>;

export const safeProblemRelations = {
  'PC-AUTH-0001': {
    status: 401,
    truthState: 'DENIED',
    retryable: false,
    problemType: 'https://errors.openpc.local/hidden-or-not-found',
  },
  'PC-AUTH-0002': {
    status: 403,
    truthState: 'DENIED',
    retryable: false,
    problemType: 'https://errors.openpc.local/hidden-or-not-found',
  },
  'PC-AUTH-0003': {
    status: 403,
    truthState: 'DENIED',
    retryable: false,
    problemType: 'https://errors.openpc.local/hidden-or-not-found',
  },
  'PC-AUTH-0005': {
    status: 404,
    truthState: 'DENIED',
    retryable: false,
    problemType: 'https://errors.openpc.local/hidden-or-not-found',
  },
  'PC-AUTH-0006': {
    status: 403,
    truthState: 'DENIED',
    retryable: false,
    problemType: 'https://errors.openpc.local/hidden-or-not-found',
  },
  'PC-RUNTIME-3007': {
    status: 409,
    truthState: 'FAILED',
    retryable: false,
    problemType: 'https://errors.openpc.local/conflict',
  },
  'PC-INTEGRATION-5001': {
    status: 503,
    truthState: 'UNAVAILABLE',
    retryable: true,
    problemType: 'https://errors.openpc.local/unavailable',
  },
  'PC-DATA-6004': {
    status: 400,
    truthState: 'FAILED',
    retryable: false,
    problemType: 'https://errors.openpc.local/invalid-request',
  },
  'PC-DATA-6007': {
    status: 412,
    truthState: 'STALE',
    retryable: false,
    problemType: 'https://errors.openpc.local/stale',
  },
} as const;

export const safeProblemSchema = z
  .object({
    type: z.string().url(),
    title: z.string().min(1).max(160),
    status: z.number().int().min(400).max(599),
    code: z.string().regex(/^PC-[A-Z][A-Z0-9]{1,15}-[0-9]{4}$/),
    traceId: z.string().regex(uuidV7Pattern),
    truthState: z.enum(truthStates),
    retryable: z.boolean(),
  })
  .strict()
  .superRefine((value, context) => {
    const relation = safeProblemRelations[value.code as keyof typeof safeProblemRelations];
    if (!relation) return;
    if (
      value.status !== relation.status ||
      value.truthState !== relation.truthState ||
      value.retryable !== relation.retryable ||
      value.type !== relation.problemType
    ) {
      context.addIssue({ code: 'custom', message: 'problem fields do not match error registry' });
    }
  });

export type SafeProblem = z.infer<typeof safeProblemSchema>;

export interface UiEvent {
  readonly type: 'snapshot-invalidated' | 'context-changed' | 'module-removed';
  readonly routeId?: string;
  readonly extensionId?: string;
}

/** Evidence-only UiProcessAcceptanceReceiptV1 projection; excludes protected payload. */
export interface UiProcessAcceptanceReceipt {
  readonly receiptId: string;
  readonly validationId: string;
  readonly sourceRecordSha256: string;
  readonly buildDigest: string;
  readonly browserProfile: string;
  readonly assistiveTechnologyProfile: string;
  readonly personaId: string;
  readonly routeId: string;
  readonly processDomainId: string;
  readonly truthState: TruthState;
  readonly uiIntent: ActionIntent;
  readonly apiFixtureId: string;
  readonly responsiveProfile: string;
  readonly theme: string;
  readonly density: string;
  readonly locale: string;
  readonly timeZone: string;
  readonly assertionResults: readonly string[];
  readonly backendReauthorizationResult: 'PASS';
  readonly antiLeakageResult: 'PASS';
  readonly evidenceDigests: readonly string[];
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly stableProblems: readonly string[];
  readonly result: 'PASS';
}

/**
 * Evidence-only V2 aggregate receipt. V1 retains its immutable historical
 * identity; V2 holds the closed per-environment assertion topology required
 * by I08's factorized execution correction.
 */
export interface UiProcessAcceptanceReceiptV2 {
  readonly type: 'UiProcessAcceptanceReceiptV2';
  readonly schemaId: 23003;
  readonly schemaVersion: '2.0.0';
  readonly purpose: 'openpc:ui-process-acceptance-receipt:v2';
  readonly receiptId: string;
  readonly binding: Readonly<Record<string, string>>;
  readonly row: {
    readonly validationId: string;
    readonly catalogueDigest: string;
    readonly sourceRecordSha256: string;
    readonly acceptedRecordSha256: string;
    readonly acceptedAtomicTupleSha256: string;
    readonly routeId: string;
    readonly routePath: string;
    readonly processDomainId: string;
    readonly truthState: TruthState;
    readonly uiIntent: ActionIntent;
    readonly apiFixtureId: string;
    readonly primaryPersonaId: string;
  };
  readonly runId: string;
  readonly shardId: string;
  readonly attempt: number;
  readonly executions: readonly UiProcessAcceptanceExecutionV2[];
  readonly evidence: readonly UiProcessAcceptanceArtifactV2[];
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly stableProblems: readonly string[];
  readonly result: 'AUTOMATED_ROW_PASS' | 'FAIL' | 'INCOMPLETE';
}

export interface UiProcessAcceptanceExecutionV2 {
  readonly environmentId: string;
  readonly environmentDigest: string;
  readonly browserProfile: string;
  readonly assistiveTechnologyProfile: 'NONE_AUTOMATED' | string;
  readonly assertions: readonly UiProcessAcceptanceAssertionV2[];
}

export interface UiProcessAcceptanceAssertionV2 {
  readonly assertionKey: string;
  readonly method:
    | 'BASELINE_RENDER'
    | 'BROWSER_ACTION'
    | 'DIRECT_BFF'
    | 'PROFILE_RENDER'
    | 'PERSONA_RENDER'
    | 'RENDER_EQUIVALENCE'
    | 'BROWSER_TRANSITION'
    | 'AUTOMATED_ACCESSIBILITY'
    | 'COMPLETE_PROCESS'
    | 'MANUAL_ASSISTIVE_TECHNOLOGY';
  readonly expectedObservationDigest: string;
  readonly observedObservationDigest: string;
  readonly evidenceRefs: readonly string[];
  readonly result: 'PASS' | 'FAIL' | 'INCOMPLETE';
}

export interface UiProcessAcceptanceArtifactV2 {
  readonly artifactId: string;
  readonly path: string;
  readonly sha256: string;
  readonly byteLength: number;
  readonly kind: string;
}

export function isActionIntent(value: string): value is ActionIntent {
  return (actionIntents as readonly string[]).includes(value);
}

export function isTruthState(value: string): value is TruthState {
  return (truthStates as readonly string[]).includes(value);
}
