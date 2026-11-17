import { createHash } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import {
  notificationBinding,
  notificationCommand,
  notificationQuery,
  notificationView,
  type NotificationView,
} from '../../../../lib/notification-workflow';
import {
  acknowledgeNotificationSchema,
  createNotificationSchema,
} from '../../../../../../services/control-api/src/notifications/contracts';
import {
  collectionResponseSchema,
  notificationResponseSchema,
  operationResponseSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';
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
// Exact registered semantics from deploy/compose/local/migrate.sh at 5801ae6c.
const action = (
  id: string,
  resource: string,
  operation: string,
  risk: string,
  evidence: string,
) => ({
  id,
  digest: `sha256:${createHash('sha256').update([id, resource, operation, risk, 'false', 'false', 'true', 'AUTHORIZED_TYPE_ONLY', 'AUTHORIZED_MINIMAL', evidence].join('\0')).digest('hex')}`,
});
const createAction = action(
  'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1',
  'notifications',
  'CREATE',
  'STANDARD',
  'CREATE_NOTIFICATIONS',
);
const ackAction = action(
  'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1',
  'notification',
  'UPDATE',
  'LOW',
  'UPDATE_NOTIFICATION',
);
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
    cache: 'no-store',
    redirect: 'error',
    headers,
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
  }).catch(() => undefined);
}
function validOperation(operation: {
  actionIntentId: string;
  intentDigest: string;
  resourceRef: string | null;
}) {
  const registered = [createAction, ackAction].find(
    (entry) => entry.id === operation.actionIntentId,
  );
  return (
    registered !== undefined &&
    operation.intentDigest === registered.digest &&
    operation.resourceRef?.startsWith('urn:openpc:resource:') === true
  );
}
async function finish(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  value: NotificationView | NextResponse,
  status = 200,
) {
  if (!(await current(request, runtime, session))) return safeProblem('PC-AUTH-0005', request);
  return isResponse(value)
    ? value
    : NextResponse.json(notificationView.parse(value), { status, headers: noStore });
}
export async function readNotificationWorkbench(request: NextRequest) {
  const authorized = await context(request);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const entries = [...request.nextUrl.searchParams];
  const query = notificationQuery.safeParse({ view: 'LIST', ...Object.fromEntries(entries) });
  if (new Set(entries.map(([key]) => key)).size !== entries.length || !query.success)
    return safeProblem('PC-DATA-6004', request);
  const input = query.data;
  if ('actorKey' in input && input.actorKey !== authorized.binding.actorKey)
    return safeProblem('PC-AUTH-0005', request);
  if (input.view === 'LIST') {
    const parameters = new URLSearchParams({ limit: input.limit, sort: input.sort });
    if (input.cursor) parameters.set('cursor', input.cursor);
    if (input.filter) parameters.set('filter', input.filter);
    const response = await fetchOwner(request, runtime, session, `notifications?${parameters}`);
    const page = await ownerJson(
      response,
      collectionResponseSchema(notificationResponseSchema),
      request,
    );
    if (isResponse(page)) return finish(request, runtime, session, page);
    if (
      page.items.length > Number(input.limit) ||
      page.items.some(
        (item) =>
          item.participantId !== `urn:openpc:participant:${session.participantId}` ||
          !item.notificationId.startsWith('urn:openpc:resource:'),
      ) ||
      (page.authorizedEmpty &&
        (page.items.length !== 0 || page.total !== '0' || page.completeness !== 'COMPLETE'))
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return finish(request, runtime, session, { ...authorized.binding, kind: 'LIST', page });
  }
  if (input.view === 'DETAIL') {
    const response = await fetchOwner(
      request,
      runtime,
      session,
      `notifications/${encodeURIComponent(input.notificationRef)}`,
    );
    const item = await ownerJson(response, notificationResponseSchema, request);
    if (isResponse(item)) return finish(request, runtime, session, item);
    const etag = `"${digest({ resourceId: input.notificationRef.slice(-36), revision: item.revision })}"`;
    if (
      item.notificationId !== input.notificationRef ||
      item.participantId !== `urn:openpc:participant:${session.participantId}` ||
      response?.headers.get('etag') !== etag
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return finish(request, runtime, session, {
      ...authorized.binding,
      kind: 'DETAIL',
      notification: item,
      etag,
    });
  }
  const response = await fetchOwner(request, runtime, session, `operations/${input.operationId}`);
  const operation = await ownerJson(
    response,
    operationResponseSchema.omit({ signingResult: true }).strict(),
    request,
  );
  if (isResponse(operation)) return finish(request, runtime, session, operation);
  if (!validOperation(operation) || operation.operationId !== input.operationId)
    return safeProblem('PC-INTEGRATION-5001', request);
  return finish(request, runtime, session, { ...authorized.binding, kind: 'OPERATION', operation });
}
export async function mutateNotificationWorkbench(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const authorized = await context(request, true);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const parsed = notificationCommand.safeParse(await readPublicCommand(request, 8192));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data;
  if (input.actorKey !== authorized.binding.actorKey) return safeProblem('PC-AUTH-0005', request);
  const selected = input.command === 'CREATE' ? createAction : ackAction;
  const envelope = {
    actionIntentId: selected.id,
    actionIntentDigest: selected.digest,
    reason: input.reason,
  };
  const body =
    input.command === 'CREATE'
      ? createNotificationSchema.parse({
          ...envelope,
          participantId: `urn:openpc:participant:${session.participantId}`,
          severity: input.severity,
          resourceRef: input.resourceRef,
          messageKey: input.messageKey,
        })
      : acknowledgeNotificationSchema.parse({
          ...envelope,
          targetRef: input.notificationRef,
          expectedRevision: input.expectedRevision,
          inputDigest: digest({
            actionIntentId: selected.id,
            targetRef: input.notificationRef,
            expectedRevision: input.expectedRevision,
            transition: 'ACKNOWLEDGE',
          }),
        });
  if (
    input.command === 'ACKNOWLEDGE' &&
    input.etag !==
      `"${digest({ resourceId: input.notificationRef.slice(-36), revision: input.expectedRevision })}"`
  )
    return safeProblem('PC-DATA-6007', request);
  const token = await csrf(runtime, session, selected.id).catch(() => undefined);
  if (!token || !(await current(request, runtime, session)))
    return safeProblem('PC-AUTH-0005', request);
  const key = `workbench-notification-${input.requestKey}`;
  const response = await fetchOwner(
    request,
    runtime,
    session,
    input.command === 'CREATE'
      ? 'notifications'
      : `notifications/${encodeURIComponent(input.notificationRef)}/acknowledge`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'OpenPC-Action-Intent-Digest': selected.digest,
        'Idempotency-Key': key,
        ...(input.command === 'ACKNOWLEDGE' ? { 'If-Match': input.etag } : {}),
      },
      body: JSON.stringify(body),
    },
  );
  const operation = await ownerJson(
    response,
    operationResponseSchema.omit({ signingResult: true }).strict(),
    request,
  );
  if (isResponse(operation)) return finish(request, runtime, session, operation);
  if (
    response?.status !== 202 ||
    !validOperation(operation) ||
    operation.actionIntentId !== selected.id ||
    operation.idempotencyKey !== key ||
    (input.command === 'ACKNOWLEDGE' && operation.resourceRef !== input.notificationRef)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return finish(
    request,
    runtime,
    session,
    { ...authorized.binding, kind: 'OPERATION', operation },
    202,
  );
}
