import { createHash } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  protectedAccessView,
  protectedConsumptionResponse,
  protectedObjectView,
} from '../../../../../../services/control-api/src/evidence/protected-contracts';
import { collectionResponseSchema } from '../../../../../../services/control-api/src/configuration/resource-contracts';
import { protectedCatalogueSchema } from '../../../../lib/protected-proof-catalogue';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  readPublicCommand,
  safeProblem,
  sameOrigin,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { csrf, digest, isResponse, ownerJson, publicHeaders } from './local-governance-api';
const noStore = { 'Cache-Control': 'no-store' };
const action = 'ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1';
const actionDigest = `sha256:${createHash('sha256')
  .update(
    [
      action,
      'protected-proof-access',
      'EXPORT',
      'STANDARD',
      'false',
      'false',
      'true',
      'AUTHORIZED_ONLY',
      'REDACTED',
      'PROTECTED_PROOF_CONSUMPTION',
    ].join('\0'),
  )
  .digest('hex')}`;
const actorKey = (s: IdentitySession) =>
  digest({
    participantId: s.participantId,
    privacyDomainId: s.privacyDomainId,
    principalId: s.principalId,
    sessionId: s.sessionId,
    contextEpoch: s.contextEpoch,
  });
const actor = (s: IdentitySession) => ({
  participantId: s.participantId,
  privacyDomainId: s.privacyDomainId!,
  principalId: s.principalId,
  sessionId: s.sessionId,
  contextEpoch: s.contextEpoch,
});
const objectSummary = (object: z.infer<typeof protectedObjectView>) => ({
  objectRef: object.objectRef,
  objectVersion: object.objectVersion,
  purpose: object.purpose,
  caseReference: object.caseReference,
  retainUntil: object.retainUntil,
  createdAt: object.createdAt,
  updatedAt: object.updatedAt,
});
async function context(request: NextRequest, mutation = false) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  if (mutation && !sameOrigin(request)) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  return { runtime, session };
}
async function current(request: NextRequest, runtime: LocalConfig, session: IdentitySession) {
  const latest = await authenticated(request, runtime);
  return latest?.contextMode === 'PARTICIPANT' && actorKey(latest) === actorKey(session);
}
async function readAccess(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  id: string,
) {
  const ref = `urn:openpc:resource:${id}`;
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/protected-proof-access/${encodeURIComponent(ref)}`,
    {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
    },
  ).catch(() => undefined);
  const access = await ownerJson(response, protectedAccessView, request);
  if (isResponse(access)) return access;
  if (
    access.accessRef !== ref ||
    access.participantId !== `urn:openpc:participant:${session.participantId}` ||
    access.privacyDomainId !== session.privacyDomainId
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return access;
}
export async function readProtectedProofWorkbench(request: NextRequest) {
  const ctx = await context(request);
  if (isResponse(ctx)) return ctx;
  const query = z
    .union([
      z.strictObject({ accessId: z.uuidv7() }),
      z.strictObject({ objectId: z.uuidv7() }),
      z.strictObject({
        catalogue: z.enum(['objects', 'access']),
        cursor: z.string().min(1).max(2048).optional(),
      }),
    ])
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    new Set(request.nextUrl.searchParams.keys()).size !== [...request.nextUrl.searchParams].length
  )
    return safeProblem('PC-DATA-6004', request);
  if ('catalogue' in query.data) {
    const { catalogue, cursor } = query.data;
    const collection = catalogue === 'objects' ? 'protected-proofs' : 'protected-proof-access';
    const response = await fetch(
      `${ctx.runtime.publicApiUrl}/api/v1/${collection}?${new URLSearchParams({ limit: '20', sort: '-updatedAt', ...(cursor ? { cursor } : {}) })}`,
      {
        cache: 'no-store',
        headers: publicHeaders(ctx.runtime, ctx.session),
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
      },
    ).catch(() => undefined);
    const schema = z.union([
      collectionResponseSchema(protectedObjectView),
      collectionResponseSchema(protectedAccessView),
    ]);
    const page = await ownerJson(response, schema, request);
    if (isResponse(page)) return page;
    if (
      page.items.some(
        (item) =>
          item.participantId !== `urn:openpc:participant:${ctx.session.participantId}` ||
          item.privacyDomainId !== ctx.session.privacyDomainId,
      )
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const projected = protectedCatalogueSchema.safeParse({
      ...page,
      catalogue,
      actorKey: actorKey(ctx.session),
      actor: actor(ctx.session),
      items: page.items.map((item) =>
        'accessRef' in item
          ? {
              accessRef: item.accessRef,
              objectRef: item.object.objectRef,
              objectVersion: item.object.objectVersion,
              purpose: item.purpose,
              caseReference: item.caseReference,
              recipientPrincipalId: item.recipientPrincipalId,
              state: item.state,
              expiresAt: item.expiresAt,
              createdAt: item.createdAt,
              updatedAt: item.updatedAt,
            }
          : objectSummary(item),
      ),
    });
    if (!projected.success || (cursor && projected.data.nextCursor === cursor))
      return safeProblem('PC-INTEGRATION-5001', request);
    if (!(await current(request, ctx.runtime, ctx.session)))
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json(projected.data, { headers: noStore });
  }
  if ('objectId' in query.data) {
    const ref = `urn:openpc:resource:${query.data.objectId}`;
    const response = await fetch(
      `${ctx.runtime.publicApiUrl}/api/v1/protected-proofs/${encodeURIComponent(ref)}`,
      {
        cache: 'no-store',
        headers: publicHeaders(ctx.runtime, ctx.session),
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
      },
    ).catch(() => undefined);
    const object = await ownerJson(response, protectedObjectView, request);
    if (isResponse(object)) return object;
    if (
      object.objectRef !== ref ||
      object.participantId !== `urn:openpc:participant:${ctx.session.participantId}` ||
      object.privacyDomainId !== ctx.session.privacyDomainId
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    if (!(await current(request, ctx.runtime, ctx.session)))
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json(
      { actorKey: actorKey(ctx.session), actor: actor(ctx.session), object: objectSummary(object) },
      { headers: noStore },
    );
  }
  const access = await readAccess(request, ctx.runtime, ctx.session, query.data.accessId);
  if (isResponse(access)) return access;
  if (!(await current(request, ctx.runtime, ctx.session)))
    return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(
    {
      actorKey: actorKey(ctx.session),
      actor: actor(ctx.session),
      access,
      accessDigest: digest(access),
    },
    { headers: noStore },
  );
}
export async function consumeProtectedProofWorkbench(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const ctx = await context(request, true);
  if (isResponse(ctx)) return ctx;
  const parsed = z
    .strictObject({
      accessId: z.uuidv7(),
      actorKey: z.string(),
      accessDigest: z.string(),
      requestKey: z.uuid(),
    })
    .safeParse(await readPublicCommand(request, 4096));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const { runtime, session } = ctx,
    input = parsed.data;
  if (input.actorKey !== actorKey(session)) return safeProblem('PC-AUTH-0005', request);
  const access = await readAccess(request, runtime, session, input.accessId);
  if (isResponse(access)) return access;
  if (
    access.recipientPrincipalId !== session.principalId ||
    access.state !== 'AVAILABLE' ||
    access.revision !== '1' ||
    digest(access) !== input.accessDigest
  )
    return safeProblem('PC-AUTH-0005', request);
  const csrfToken = await csrf(runtime, session, action);
  if (!csrfToken) return safeProblem('PC-AUTH-0005', request);
  if (!(await current(request, runtime, session))) return safeProblem('PC-AUTH-0005', request);
  const body = {
    actionIntentId: action,
    actionIntentDigest: actionDigest,
    reason: 'Consume the exact approved protected proof access.',
    targetRef: access.accessRef,
    expectedRevision: '1',
    object: access.object,
    purpose: access.purpose,
    caseReference: access.caseReference,
    recipientPrincipalId: access.recipientPrincipalId,
    expiresAt: access.expiresAt,
  };
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/protected-proof-access/${encodeURIComponent(access.accessRef)}/consume`,
    {
      method: 'POST',
      cache: 'no-store',
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(20000)]),
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Idempotency-Key': `protected-delivery-${input.requestKey}`,
        'OpenPC-Action-Intent-Digest': actionDigest,
        'If-Match': `"${digest({ resourceId: input.accessId, revision: '1' })}"`,
      },
      body: JSON.stringify(body),
    },
  ).catch(() => undefined);
  if (!response)
    return NextResponse.json(
      {
        truthState: 'UNKNOWN',
        reconciliation: 'READ_PROTECTED_ACCESS',
        accessRef: access.accessRef,
      },
      { status: 202, headers: noStore },
    );
  const result = await ownerJson(response, protectedConsumptionResponse, request);
  if (isResponse(result)) return result;
  if (
    result.operation.resourceRef !== access.accessRef ||
    result.operation.actionIntentId !== action ||
    (result.disclosure &&
      (digest(result.disclosure) !== access.object.objectDigest ||
        result.disclosure.participantId !== session.participantId ||
        result.disclosure.privacyDomainId !== session.privacyDomainId ||
        digest(result.disclosure.source) !== digest(access.object.source)))
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  if (!(await current(request, runtime, session))) return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(result, { status: 202, headers: noStore });
}
export type ProtectedAccess = z.infer<typeof protectedAccessView>;
export type ProtectedConsumption = z.infer<typeof protectedConsumptionResponse>;
