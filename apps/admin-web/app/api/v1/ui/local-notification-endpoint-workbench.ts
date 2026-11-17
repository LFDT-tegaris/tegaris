import { createHash } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  endpointCommand,
  endpointCreateAction,
  endpointUpdateAction,
  endpointReplacements,
  endpointQuery,
  endpointView,
  endpointRecord,
  endpointOperation,
  endpointUnknownProblem,
  endpointVerifyActionId,
  endpointRequestKey,
  endpointRef,
  type EndpointView,
} from '../../../../lib/notification-endpoint-workflow';
import { notificationBinding } from '../../../../lib/notification-workflow';
import {
  createNotificationEndpointSchema,
  updateNotificationEndpointSchema,
  verifyNotificationEndpointSchema,
} from '../../../../../../services/control-api/src/notifications/contracts';
import { collectionResponseSchema } from '../../../../../../services/control-api/src/configuration/resource-contracts';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  readPublicCommand,
  responseIds,
  safeProblem,
  sameOrigin,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { csrf, digest, isResponse, ownerJson, publicHeaders } from './local-governance-api';

const noStore = { 'Cache-Control': 'no-store' };
// Registered action semantics at canonical 892e439f; no UI supplied action,
// scope, CSRF token, credential or proof is forwarded as authority.
const verifyAction = {
  id: endpointVerifyActionId,
  digest: `sha256:${createHash('sha256').update([endpointVerifyActionId, 'notification-endpoint', 'UPDATE', 'STANDARD', 'false', 'false', 'true', 'AUTHORIZED_TYPE_ONLY', 'AUTHORIZED_MINIMAL', 'UPDATE_NOTIFICATION_ENDPOINT'].join('\0')).digest('hex')}`,
};
function binding(session: IdentitySession) {
  return notificationBinding.parse({
    actor: { participantId: session.participantId, privacyDomainId: session.privacyDomainId },
    actorKey: digest({
      participantId: session.participantId,
      privacyDomainId: session.privacyDomainId,
      sessionId: session.sessionId,
      principalId: session.principalId,
      contextEpoch: session.contextEpoch,
    }),
  });
}
async function context(request: NextRequest, mutation = false) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  if (mutation && !sameOrigin(request)) return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  return { runtime, session, binding: binding(session) };
}
async function current(request: NextRequest, runtime: LocalConfig, session: IdentitySession) {
  const next = await authenticated(request, runtime);
  return (
    !!next &&
    next.contextMode === 'PARTICIPANT' &&
    !!next.privacyDomainId &&
    binding(next).actorKey === binding(session).actorKey
  );
}
async function fetchOwner(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  init?: RequestInit,
) {
  const headers = new Headers(publicHeaders(runtime, session));
  new Headers(init?.headers).forEach((value, name) => headers.set(name, value));
  return fetch(`${runtime.publicApiUrl}/api/v1/${path}`, {
    ...init,
    headers,
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
  }).catch(() => undefined);
}
function validOperation(operation: z.infer<typeof endpointOperation>) {
  return (
    ((operation.actionIntentId === verifyAction.id &&
      operation.intentDigest === verifyAction.digest) ||
      (operation.actionIntentId === endpointCreateAction.id &&
        operation.intentDigest === endpointCreateAction.digest) ||
      (operation.actionIntentId === endpointUpdateAction.id &&
        operation.intentDigest === endpointUpdateAction.digest)) &&
    endpointRef.safeParse(operation.resourceRef).success
  );
}
async function finish(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  value: EndpointView | NextResponse,
  status = 200,
) {
  if (!(await current(request, runtime, session))) return safeProblem('PC-AUTH-0005', request);
  return isResponse(value)
    ? value
    : NextResponse.json(endpointView.parse(value), { status, headers: noStore });
}

/** Shared ownerFailure maps 409 to FAILED. The endpoint's existing UNKNOWN is
 * stronger information: retain it, with fresh safe trace IDs and no upstream text. */
async function verificationResponse(response: Response | undefined, request: NextRequest) {
  if (response?.status === 409) {
    const original = endpointUnknownProblem.safeParse(
      ['application/json', 'application/problem+json'].includes(
        response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() ?? '',
      )
        ? await response.json().catch(() => undefined)
        : undefined,
    );
    if (!original.success) return safeProblem('PC-INTEGRATION-5001', request);
    const ids = responseIds(request);
    return NextResponse.json(
      endpointUnknownProblem.parse({
        type: 'https://errors.openpc.local/conflict',
        title: 'Endpoint outcome is unknown.',
        status: 409,
        code: 'PC-FACT-4001',
        truthState: 'UNKNOWN',
        retryable: false,
        traceId: ids.requestId,
      }),
      {
        status: 409,
        headers: {
          ...noStore,
          'Content-Type': 'application/problem+json',
          'X-Request-ID': ids.requestId,
          'X-Correlation-ID': ids.correlationId,
        },
      },
    );
  }
  return ownerJson(response, endpointOperation, request);
}
export async function readNotificationEndpointWorkbench(request: NextRequest) {
  const authorized = await context(request);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const entries = [...request.nextUrl.searchParams];
  const query = endpointQuery.safeParse({ view: 'LIST', ...Object.fromEntries(entries) });
  if (new Set(entries.map(([key]) => key)).size !== entries.length || !query.success)
    return safeProblem('PC-DATA-6004', request);
  const input = query.data;
  if ('actorKey' in input && input.actorKey !== authorized.binding.actorKey)
    return safeProblem('PC-AUTH-0005', request);
  if (input.view === 'LIST') {
    const parameters = new URLSearchParams({ limit: input.limit, sort: input.sort });
    if (input.filter) parameters.set('filter', input.filter);
    if (input.cursor) parameters.set('cursor', input.cursor);
    const response = await fetchOwner(
      request,
      runtime,
      session,
      `notification-endpoints?${parameters}`,
    );
    const page = await ownerJson(response, collectionResponseSchema(endpointRecord), request);
    if (isResponse(page)) return finish(request, runtime, session, page);
    if (
      response?.status !== 200 ||
      page.items.length > Number(input.limit) ||
      page.items.some(
        (item) => item.participantId !== `urn:openpc:participant:${session.participantId}`,
      ) ||
      (page.authorizedEmpty &&
        (page.items.length !== 0 || page.total !== '0' || page.completeness !== 'COMPLETE'))
    )
      return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
    return finish(request, runtime, session, { ...authorized.binding, kind: 'LIST', page });
  }
  if (input.view === 'REPLACEMENTS') {
    const response = await fetchOwner(
      request,
      runtime,
      session,
      `notification-endpoints/${encodeURIComponent(input.endpointRef)}/replacements`,
    );
    const choices = await ownerJson(response, endpointReplacements, request);
    if (isResponse(choices)) return finish(request, runtime, session, choices);
    if (
      response?.status !== 200 ||
      choices.notificationEndpointId !== input.endpointRef ||
      new Set(choices.items.map((item) => item.replacementDigest)).size !== choices.items.length
    )
      return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
    return finish(request, runtime, session, {
      ...authorized.binding,
      kind: 'REPLACEMENTS',
      choices,
    });
  }
  if (input.view === 'DETAIL') {
    const response = await fetchOwner(
      request,
      runtime,
      session,
      `notification-endpoints/${encodeURIComponent(input.endpointRef)}`,
    );
    const item = await ownerJson(response, endpointRecord, request);
    if (isResponse(item)) return finish(request, runtime, session, item);
    const etag = `"${digest({ resourceId: input.endpointRef.slice(-36), revision: item.revision })}"`;
    if (
      response?.status !== 200 ||
      item.notificationEndpointId !== input.endpointRef ||
      item.participantId !== `urn:openpc:participant:${session.participantId}` ||
      response.headers.get('etag') !== etag
    )
      return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
    return finish(request, runtime, session, {
      ...authorized.binding,
      kind: 'DETAIL',
      endpoint: item,
      etag,
    });
  }
  const response = await fetchOwner(request, runtime, session, `operations/${input.operationId}`);
  const operation = await ownerJson(response, endpointOperation, request);
  if (isResponse(operation)) return finish(request, runtime, session, operation);
  if (
    response?.status !== 200 ||
    !validOperation(operation) ||
    operation.operationId !== input.operationId
  )
    return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
  return finish(request, runtime, session, { ...authorized.binding, kind: 'OPERATION', operation });
}
export async function mutateNotificationEndpointWorkbench(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const authorized = await context(request, true);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const parsed = endpointCommand.safeParse(await readPublicCommand(request, 8192));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data;
  if (input.actorKey !== authorized.binding.actorKey) return safeProblem('PC-AUTH-0005', request);
  if (input.command === 'UPDATE' || input.command === 'REVIEW_UPDATE') {
    if (
      input.etag !==
      `"${digest({ resourceId: input.endpointRef.slice(-36), revision: input.expectedRevision })}"`
    )
      return safeProblem('PC-DATA-6007', request);
    const body = updateNotificationEndpointSchema.parse({
      actionIntentId: endpointUpdateAction.id,
      actionIntentDigest: endpointUpdateAction.digest,
      expectedRevision: input.expectedRevision,
      replacementDigest: input.replacementDigest,
      reason: input.reason,
    });
    const candidateDigest = digest(body);
    if (input.command === 'REVIEW_UPDATE') {
      const response = await fetchOwner(
        request,
        runtime,
        session,
        `notification-endpoints/${encodeURIComponent(input.endpointRef)}/replacements`,
      );
      const choices = await ownerJson(response, endpointReplacements, request);
      if (isResponse(choices)) return finish(request, runtime, session, choices);
      if (response?.status !== 200 || choices.notificationEndpointId !== input.endpointRef)
        return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
      const selected = choices.items.filter(
        (item) => item.replacementDigest === input.replacementDigest,
      );
      if (choices.revision !== input.expectedRevision || selected.length !== 1 || !selected[0])
        return finish(request, runtime, session, safeProblem('PC-DATA-6007', request));
      return finish(request, runtime, session, {
        ...authorized.binding,
        kind: 'UPDATE_REVIEW',
        request: { ...input, command: 'UPDATE', candidateDigest },
        choice: selected[0],
        stepUp: {
          actionIntentId: endpointUpdateAction.id,
          actionIntentDigest: endpointUpdateAction.digest,
          resourceId: input.endpointRef.slice(-36),
          resourceDigest: candidateDigest,
        },
      });
    }
    if (input.candidateDigest !== candidateDigest) return safeProblem('PC-DATA-6007', request);
    const token = await csrf(runtime, session, endpointUpdateAction.id).catch(() => undefined);
    if (!token || !(await current(request, runtime, session)))
      return safeProblem('PC-AUTH-0005', request);
    const key = endpointRequestKey(input.requestKey);
    // No choice refresh during exact replay: the original digest/revision/key
    // reach the existing atomic owner's committed replay or admission checks.
    const response = await fetchOwner(
      request,
      runtime,
      session,
      `notification-endpoints/${encodeURIComponent(input.endpointRef)}`,
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
          'OpenPC-Action-Intent-Digest': endpointUpdateAction.digest,
          'Idempotency-Key': key,
          'If-Match': input.etag,
        },
        body: JSON.stringify(body),
      },
    );
    const operation = await verificationResponse(response, request);
    if (isResponse(operation)) return finish(request, runtime, session, operation);
    if (
      response?.status !== 202 ||
      !validOperation(operation) ||
      operation.actionIntentId !== endpointUpdateAction.id ||
      operation.resourceRef !== input.endpointRef ||
      operation.idempotencyKey !== key
    )
      return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
    return finish(
      request,
      runtime,
      session,
      { ...authorized.binding, kind: 'OPERATION', operation },
      202,
    );
  }
  if (input.command === 'CREATE' || input.command === 'REVIEW_CREATE') {
    const body = createNotificationEndpointSchema.parse({
      actionIntentId: endpointCreateAction.id,
      actionIntentDigest: endpointCreateAction.digest,
      participantId: `urn:openpc:participant:${session.participantId}`,
      channel: input.channel,
      destinationRef: input.destinationRef,
      arbitraryEgress: false,
      reason: input.reason,
    });
    const candidateDigest = digest(body);
    if (input.command === 'REVIEW_CREATE') {
      // A review is not installation/profile admission. Only public CREATE can
      // admit this candidate, consume real WebAuthn and persist a DISABLED row.
      return finish(request, runtime, session, {
        ...authorized.binding,
        kind: 'CREATE_REVIEW',
        request: { ...input, command: 'CREATE', candidateDigest },
        stepUp: {
          actionIntentId: endpointCreateAction.id,
          actionIntentDigest: endpointCreateAction.digest,
          // This is the review correlation ID, not a caller-chosen aggregate.
          resourceId: input.requestKey,
          resourceDigest: candidateDigest,
        },
      });
    }
    if (input.candidateDigest !== candidateDigest) return safeProblem('PC-DATA-6007', request);
    const token = await csrf(runtime, session, endpointCreateAction.id).catch(() => undefined);
    if (!token || !(await current(request, runtime, session)))
      return safeProblem('PC-AUTH-0005', request);
    const key = endpointRequestKey(input.requestKey);
    const response = await fetchOwner(request, runtime, session, 'notification-endpoints', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'OpenPC-Action-Intent-Digest': endpointCreateAction.digest,
        'Idempotency-Key': key,
      },
      body: JSON.stringify(body),
    });
    const operation = await ownerJson(response, endpointOperation, request);
    if (isResponse(operation)) return finish(request, runtime, session, operation);
    if (
      response?.status !== 202 ||
      !validOperation(operation) ||
      operation.actionIntentId !== endpointCreateAction.id ||
      operation.idempotencyKey !== key
    )
      return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
    return finish(
      request,
      runtime,
      session,
      { ...authorized.binding, kind: 'OPERATION', operation },
      202,
    );
  }
  if (
    input.etag !==
    `"${digest({ resourceId: input.endpointRef.slice(-36), revision: input.expectedRevision })}"`
  )
    return safeProblem('PC-DATA-6007', request);
  const body = verifyNotificationEndpointSchema.parse({
    actionIntentId: verifyAction.id,
    actionIntentDigest: verifyAction.digest,
    reason: input.reason,
    targetRef: input.endpointRef,
    expectedRevision: input.expectedRevision,
    inputDigest: digest({
      actionIntentId: verifyAction.id,
      targetRef: input.endpointRef,
      expectedRevision: input.expectedRevision,
      transition: 'VERIFY',
    }),
  });
  const token = await csrf(runtime, session, verifyAction.id).catch(() => undefined);
  if (!token || !(await current(request, runtime, session)))
    return safeProblem('PC-AUTH-0005', request);
  // Do not refresh or alter the original revision/body here. Exact replay must
  // reach the owner's ATTACHED/PROVED/UNKNOWN handling with the original key.
  const key = endpointRequestKey(input.requestKey);
  const response = await fetchOwner(
    request,
    runtime,
    session,
    `notification-endpoints/${encodeURIComponent(input.endpointRef)}/verify`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'OpenPC-Action-Intent-Digest': verifyAction.digest,
        'Idempotency-Key': key,
        'If-Match': input.etag,
      },
      body: JSON.stringify(body),
    },
  );
  const operation = await verificationResponse(response, request);
  if (isResponse(operation)) return finish(request, runtime, session, operation);
  if (
    response?.status !== 202 ||
    !validOperation(operation) ||
    operation.actionIntentId !== verifyAction.id ||
    operation.idempotencyKey !== key ||
    operation.resourceRef !== input.endpointRef
  )
    return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
  return finish(
    request,
    runtime,
    session,
    { ...authorized.binding, kind: 'OPERATION', operation },
    202,
  );
}
