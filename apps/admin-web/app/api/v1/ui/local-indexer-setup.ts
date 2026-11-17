import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  indexerSetupAction,
  indexerSetupBody,
  indexerSetupKind,
  type IndexerSetupKind,
} from './indexer-setup-contract';
import { csrf, digest, isResponse, ownerJson, publicHeaders } from './local-governance-api';
import {
  authenticated,
  openBffPayload,
  safeProblem,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import {
  indexerProfileResponseSchema,
  projectionPlanResponseSchema,
  operationResponseSchema,
  runtimeTargetResponseSchema,
  runtimeActivationCandidateResponseSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';
const noStore = { 'Cache-Control': 'no-store' };
const indexerView: z.ZodType<
  | z.infer<typeof indexerProfileResponseSchema>
  | z.infer<typeof projectionPlanResponseSchema>
  | z.infer<typeof runtimeTargetResponseSchema>
> = z.union([
  indexerProfileResponseSchema,
  projectionPlanResponseSchema,
  runtimeTargetResponseSchema,
]);
const actor = (session: IdentitySession) => ({
  sessionId: session.sessionId,
  principalId: session.principalId,
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId!,
  contextEpoch: session.contextEpoch,
});
const reviewSchema = z.strictObject({
  kind: indexerSetupKind,
  actor: z.strictObject({
    sessionId: z.uuidv7(),
    principalId: z.uuidv7(),
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    contextEpoch: z.string(),
  }),
  issuedAt: z.number().int().nonnegative(),
  key: z.uuid(),
  targetRef: z
    .string()
    .regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u)
    .optional(),
  body: z.record(z.string(), z.unknown()),
});
export async function previewIndexerSetup(
  runtime: LocalConfig,
  session: IdentitySession,
  input: {
    kind: IndexerSetupKind;
    fields: Record<string, unknown>;
    reason: string;
    requestKey: string;
  },
  request: NextRequest,
) {
  try {
    let fields = input.fields;
    let targetRef: string | undefined;
    if (input.kind === 'runtime-activation') {
      const selected = runtimeActivationCandidateResponseSchema
        .pick({ targetRef: true, expectedRevision: true })
        .strict()
        .parse(fields);
      targetRef = selected.targetRef;
      const url = `${runtime.publicApiUrl}/api/v1/runtime-targets/${encodeURIComponent(targetRef)}`;
      const options = {
        headers: publicHeaders(runtime, session),
        cache: 'no-store' as const,
        signal: AbortSignal.timeout(15000),
      };
      const target = await ownerJson(
        await fetch(url, options).catch(() => undefined),
        runtimeTargetResponseSchema,
        request,
      );
      if (isResponse(target)) return target;
      if (
        target.targetId !== targetRef ||
        target.participantId !== `urn:openpc:participant:${session.participantId}`
      )
        return safeProblem('PC-INTEGRATION-5001', request);
      const candidate = await ownerJson(
        await fetch(`${url}/activation-candidate`, options).catch(() => undefined),
        runtimeActivationCandidateResponseSchema,
        request,
      );
      if (isResponse(candidate)) return candidate;
      if (
        candidate.targetRef !== targetRef ||
        candidate.expectedRevision !== selected.expectedRevision ||
        target.revision !== selected.expectedRevision ||
        !candidate.replacementDigest
      )
        return safeProblem('PC-DATA-6007', request);
      const current = await authenticated(request, runtime);
      if (!current || digest(actor(current)) !== digest(actor(session)))
        return safeProblem('PC-AUTH-0005', request);
      fields = {
        expectedRevision: candidate.expectedRevision,
        replacementDigest: candidate.replacementDigest,
      };
    }
    const body = indexerSetupBody(input.kind, fields, input.reason, session.participantId);
    return NextResponse.json(
      {
        actor: actor(session),
        preview: targetRef ? { targetRef, ...body } : body,
        authority: 'NONE',
        reviewToken: sealBffPayload(
          {
            kind: input.kind,
            actor: actor(session),
            issuedAt: Date.now(),
            key: input.requestKey,
            ...(targetRef ? { targetRef } : {}),
            body,
          },
          runtime.cookieKey,
          'indexer-setup-review',
        ),
      },
      { headers: noStore },
    );
  } catch {
    process.stderr.write(
      JSON.stringify({
        event: 'ordinary_setup_preview_rejected',
        kind: input.kind,
        stage: 'candidate_review',
      }) + '\n',
    );
    return safeProblem('PC-DATA-6004', request);
  }
}
export async function executeIndexerSetup(
  runtime: LocalConfig,
  session: IdentitySession,
  token: string,
  request: NextRequest,
) {
  const opened = reviewSchema.safeParse(
    openBffPayload(token, runtime.cookieKey, 'indexer-setup-review'),
  );
  if (
    !opened.success ||
    digest(opened.data.actor) !== digest(actor(session)) ||
    opened.data.issuedAt > Date.now() ||
    Date.now() - opened.data.issuedAt > 1800000
  )
    return safeProblem('PC-AUTH-0005', request);
  const review = opened.data,
    action = indexerSetupAction(review.kind);
  const parsed = action.schema.safeParse(review.body);
  if (
    !parsed.success ||
    digest(parsed.data) !== digest(review.body) ||
    parsed.data.actionIntentId !== action.id ||
    parsed.data.actionIntentDigest !== action.digest ||
    (review.kind === 'indexers' &&
      review.body.participantId !== `urn:openpc:participant:${session.participantId}`) ||
    (review.kind === 'projections' && review.body.readiness !== 'UNKNOWN') ||
    (review.kind === 'runtime-activation' ? !review.targetRef : review.targetRef !== undefined)
  )
    return safeProblem('PC-AUTH-0005', request);
  const csrfToken = await csrf(runtime, session, action.id);
  const current = await authenticated(request, runtime);
  if (!csrfToken || !current || digest(actor(current)) !== digest(actor(session)))
    return safeProblem('PC-AUTH-0005', request);
  const target =
    review.kind === 'runtime-activation'
      ? review.targetRef
      : review.kind === 'projection-validation'
        ? String(review.body.targetRef)
        : undefined;
  const key = `workbench-indexer-${review.key}`;
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/${action.collection}${target ? `/${encodeURIComponent(target)}${review.kind === 'runtime-activation' ? '' : '/recover'}` : ''}`,
    {
      method: review.kind === 'runtime-activation' ? 'PATCH' : 'POST',
      cache: 'no-store',
      signal: AbortSignal.timeout(20000),
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Idempotency-Key': key,
        'OpenPC-Action-Intent-Digest': action.digest,
        ...(target
          ? {
              'If-Match': `"${digest({ resourceId: target.slice(-36), revision: review.body.expectedRevision })}"`,
            }
          : {}),
      },
      body: JSON.stringify(review.body),
    },
  ).catch(() => undefined);
  if (!response)
    return NextResponse.json(
      { actor: actor(session), truthState: 'UNKNOWN', reconciliation: 'RETAIN_ORIGINAL_REQUEST' },
      { status: 202, headers: noStore },
    );
  const result = await ownerJson(response, operationResponseSchema, request);
  if (isResponse(result)) return result;
  if (
    result.actionIntentId !== action.id ||
    result.idempotencyKey !== key ||
    (target && result.resourceRef !== target)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  process.stderr.write(
    JSON.stringify({
      event: 'indexer_setup_operation_recorded',
      action: action.id,
      operationId: result.operationId,
      state: result.state,
      truthState: result.truthState,
    }) + '\n',
  );
  return NextResponse.json(
    { actor: actor(session), operation: result },
    { status: 202, headers: noStore },
  );
}
export async function readIndexerSetup(
  runtime: LocalConfig,
  session: IdentitySession,
  kind: IndexerSetupKind,
  resourceId: string | undefined,
  request: NextRequest,
) {
  if (!resourceId) return NextResponse.json({ actor: actor(session) }, { headers: noStore });
  const action = indexerSetupAction(kind);
  const result = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/api/v1/${action.collection}/${encodeURIComponent(`urn:openpc:resource:${resourceId}`)}`,
      {
        headers: publicHeaders(runtime, session),
        cache: 'no-store',
        signal: AbortSignal.timeout(15000),
      },
    ).catch(() => undefined),
    indexerView,
    request,
  );
  if (isResponse(result)) return result;
  const value = result as Record<string, unknown>;
  if (
    (kind === 'indexers'
      ? value.indexerProfileId
      : kind === 'runtime-activation'
        ? value.targetId
        : value.projectionPlanId) !== `urn:openpc:resource:${resourceId}` ||
    ((kind === 'indexers' || kind === 'runtime-activation') &&
      value.participantId !== `urn:openpc:participant:${session.participantId}`)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json({ actor: actor(session), result }, { headers: noStore });
}
