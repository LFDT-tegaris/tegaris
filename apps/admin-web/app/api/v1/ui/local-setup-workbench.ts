import {
  indexerSetupKind,
  indexerSetupPreview,
  indexerSetupAction,
} from './indexer-setup-contract';
import { previewIndexerSetup, executeIndexerSetup, readIndexerSetup } from './local-indexer-setup';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  collectionResponseSchema,
  createRuntimeTargetSchema,
  operationResponseSchema,
  providerProfileResponseSchema,
  runtimeTargetResponseSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  openBffPayload,
  readPublicCommand,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
} from './local-runtime';
import { csrf, digest, isResponse, ownerJson, publicHeaders } from './local-governance-api';
import { runtimeTargetProfileBindingResponseSchema } from '../../../../../../services/control-api/src/configuration/runtime-profile/contract';

type SetupResource =
  | z.infer<typeof providerProfileResponseSchema>
  | z.infer<typeof runtimeTargetResponseSchema>
  | z.infer<typeof runtimeTargetProfileBindingResponseSchema>;
const noStore = { 'Cache-Control': 'no-store' };
const kind = z.enum(['providers', 'runtime', 'runtime-profiles', ...indexerSetupKind.options]);
export const runtimeCreateAction = {
  id: 'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1',
  digest: 'sha256:70d8f23d7478cdb5931bf58e6ce55cac2bd8eb69c0c1824ff4b74633f6c6d71e',
} as const;
const binding = z.strictObject({
  sessionId: z.uuidv7(),
  principalId: z.uuidv7(),
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  contextEpoch: z.string(),
});
const actor = (session: IdentitySession) =>
  binding.parse({
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextEpoch: session.contextEpoch,
  });
const reviewSchema = z.strictObject({
  actor: binding,
  issuedAt: z.number(),
  key: z.uuid(),
  body: createRuntimeTargetSchema,
});
const commands = z.discriminatedUnion('command', [
  indexerSetupPreview,
  z.strictObject({ command: z.literal('EXECUTE_INDEXER'), reviewToken: z.string().max(16384) }),
  z.strictObject({
    command: z.literal('PREVIEW_RUNTIME'),
    requestKey: z.uuid(),
    reason: z.string().trim().min(1).max(1024),
  }),
  z.strictObject({ command: z.literal('CREATE_RUNTIME'), reviewToken: z.string().max(16384) }),
]);
async function context(request: NextRequest, mutation = false) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  if (mutation && !sameOrigin(request)) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  return { runtime, session };
}
export async function readSetupWorkbench(request: NextRequest) {
  const current = await context(request);
  if (isResponse(current)) return current;
  const { runtime, session } = current;
  async function replyInCurrentContext(response: NextResponse) {
    // An owner read may finish after another tab changes or revokes the session.
    const live = await authenticated(request, runtime);
    if (
      !live ||
      live.contextMode !== 'PARTICIPANT' ||
      !live.privacyDomainId ||
      digest(actor(live)) !== digest(actor(session))
    )
      return safeProblem('PC-AUTH-0005', request);
    return response;
  }
  const query = z
    .strictObject({
      kind: kind.optional(),
      resourceId: z.uuidv7().optional(),
      cursor: z.string().max(2048).optional(),
      operationId: z.uuidv7().optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams.keys()].length !==
      new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  const input = query.data;
  if (!input.kind && !input.resourceId && !input.cursor && !input.operationId)
    return replyInCurrentContext(
      NextResponse.json({ actor: actor(session) }, { headers: noStore }),
    );
  if (input.operationId) {
    if (
      (input.kind && !indexerSetupKind.safeParse(input.kind).success) ||
      input.resourceId ||
      input.cursor
    )
      return safeProblem('PC-DATA-6004', request);
    const result = await ownerJson(
      await fetch(`${runtime.publicApiUrl}/api/v1/operations/${input.operationId}`, {
        headers: publicHeaders(runtime, session),
        cache: 'no-store',
        signal: AbortSignal.timeout(15000),
      }).catch(() => undefined),
      operationResponseSchema,
      request,
    );
    if (isResponse(result)) return replyInCurrentContext(result);
    if (
      result.operationId !== input.operationId ||
      result.actionIntentId !==
        (input.kind && indexerSetupKind.safeParse(input.kind).success
          ? indexerSetupAction(indexerSetupKind.parse(input.kind)).id
          : runtimeCreateAction.id)
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return replyInCurrentContext(
      NextResponse.json({ actor: actor(session), operation: result }, { headers: noStore }),
    );
  }
  if (!input.kind || (input.resourceId && input.cursor))
    return safeProblem('PC-DATA-6004', request);
  const indexerKind = indexerSetupKind.safeParse(input.kind);
  if (indexerKind.success) {
    if (input.cursor) return safeProblem('PC-DATA-6004', request);
    return replyInCurrentContext(
      await readIndexerSetup(runtime, session, indexerKind.data, input.resourceId, request),
    );
  }
  const collection =
    input.kind === 'providers'
      ? 'provider-profiles'
      : input.kind === 'runtime-profiles'
        ? 'runtime-target-profile-bindings'
        : 'runtime-targets';
  const schema: z.ZodType<SetupResource> =
    input.kind === 'providers'
      ? providerProfileResponseSchema
      : input.kind === 'runtime-profiles'
        ? runtimeTargetProfileBindingResponseSchema
        : runtimeTargetResponseSchema;
  const pageSchema = collectionResponseSchema(schema);
  const path = input.resourceId
    ? `/${encodeURIComponent(`urn:openpc:resource:${input.resourceId}`)}`
    : `?${new URLSearchParams({ limit: '50', ...(input.cursor ? { cursor: input.cursor } : {}) })}`;
  const result = await ownerJson<SetupResource | z.infer<typeof pageSchema>>(
    await fetch(`${runtime.publicApiUrl}/api/v1/${collection}${path}`, {
      headers: publicHeaders(runtime, session),
      cache: 'no-store',
      signal: AbortSignal.timeout(15000),
    }).catch(() => undefined),
    input.resourceId ? schema : pageSchema,
    request,
  );
  if (isResponse(result)) return replyInCurrentContext(result);
  const rows = 'items' in result ? result.items : [result];
  if (
    rows.some(
      (row) =>
        ('participantId' in row &&
          row.participantId !== `urn:openpc:participant:${session.participantId}`) ||
        (input.resourceId &&
          ('providerProfileId' in row
            ? row.providerProfileId
            : 'bindingRef' in row
              ? row.bindingRef
              : row.targetId) !== `urn:openpc:resource:${input.resourceId}`),
    )
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return replyInCurrentContext(
    NextResponse.json({ actor: actor(session), result }, { headers: noStore }),
  );
}
export async function mutateSetupWorkbench(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const current = await context(request, true);
  if (isResponse(current)) return current;
  const { runtime, session } = current;
  const parsed = commands.safeParse(await readPublicCommand(request, 16384));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  if (parsed.data.command === 'PREVIEW_INDEXER')
    return previewIndexerSetup(runtime, session, parsed.data, request);
  if (parsed.data.command === 'EXECUTE_INDEXER')
    return executeIndexerSetup(runtime, session, parsed.data.reviewToken, request);
  if (parsed.data.command === 'PREVIEW_RUNTIME') {
    const body = createRuntimeTargetSchema.parse({
      participantId: `urn:openpc:participant:${session.participantId}`,
      actionIntentId: runtimeCreateAction.id,
      actionIntentDigest: runtimeCreateAction.digest,
      reason: parsed.data.reason,
      desiredGenerationDigest: null,
      activeGenerationDigest: null,
      xdsVersionDigest: null,
      observedAt: new Date().toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
    });
    const review = {
      actor: actor(session),
      issuedAt: Date.now(),
      key: parsed.data.requestKey,
      body,
    };
    return NextResponse.json(
      {
        actor: review.actor,
        preview: body,
        reviewToken: sealBffPayload(review, runtime.cookieKey, 'runtime-setup-review'),
        authority: 'NONE',
      },
      { headers: noStore },
    );
  }
  const opened = reviewSchema.safeParse(
    openBffPayload(parsed.data.reviewToken, runtime.cookieKey, 'runtime-setup-review'),
  );
  if (
    !opened.success ||
    digest(opened.data.actor) !== digest(actor(session)) ||
    opened.data.issuedAt > Date.now() ||
    Date.now() - opened.data.issuedAt > 1800000 ||
    opened.data.body.participantId !== `urn:openpc:participant:${session.participantId}` ||
    opened.data.body.actionIntentId !== runtimeCreateAction.id ||
    opened.data.body.actionIntentDigest !== runtimeCreateAction.digest
  )
    return safeProblem('PC-AUTH-0005', request);
  const review = opened.data;
  const token = await csrf(runtime, session, runtimeCreateAction.id);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const response = await fetch(`${runtime.publicApiUrl}/api/v1/runtime-targets`, {
    method: 'POST',
    headers: {
      ...publicHeaders(runtime, session),
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'Idempotency-Key': `workbench-runtime-${review.key}`,
      'OpenPC-Action-Intent-Digest': runtimeCreateAction.digest,
    },
    body: JSON.stringify(review.body),
    cache: 'no-store',
    signal: AbortSignal.timeout(20000),
  }).catch(() => undefined);
  if (!response)
    return NextResponse.json(
      { actor: actor(session), truthState: 'UNKNOWN', reconciliation: 'RETAIN_ORIGINAL_REQUEST' },
      { status: 202, headers: noStore },
    );
  const result = await ownerJson(response, operationResponseSchema, request);
  if (isResponse(result)) return result;
  if (
    result.actionIntentId !== runtimeCreateAction.id ||
    result.idempotencyKey !== `workbench-runtime-${review.key}`
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(
    { actor: actor(session), operation: result },
    { status: 202, headers: noStore },
  );
}
