import { createHash } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import {
  workItemActions,
  workItemRecord,
  workItemPage,
  workItemOperation,
  workItemBinding,
  workItemCommand,
  workItemQuery,
  workItemView,
  type WorkItemView,
} from '../../../../lib/work-item-workflow';
import {
  createWorkItemSchema,
  updateWorkItemSchema,
  claimWorkItemSchema,
  completeWorkItemSchema,
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
// Exact registered semantics from deploy/compose/local/migrate.sh at 6da06469.
const action = (id: string, resource: string, operation: string, evidence: string) => ({
  id,
  digest: `sha256:${createHash('sha256').update([id, resource, operation, 'STANDARD', 'false', 'false', 'true', 'AUTHORIZED_ONLY', 'REDACTED', evidence].join('\0')).digest('hex')}`,
});
const actions = {
  CREATE: action(workItemActions.CREATE, 'work-items', 'CREATE', 'CREATE_WORK_ITEMS'),
  UPDATE: action(workItemActions.UPDATE, 'work-items', 'UPDATE', 'UPDATE_WORK_ITEMS'),
  CLAIM: action(workItemActions.CLAIM, 'work-item', 'UPDATE', 'UPDATE_WORK_ITEM'),
  COMPLETE: action(workItemActions.COMPLETE, 'work-item', 'UPDATE', 'UPDATE_WORK_ITEM'),
};
function binding(session: IdentitySession) {
  return workItemBinding.parse({
    actor: {
      participantId: session.participantId,
      privacyDomainId: session.privacyDomainId,
      principalRef: `urn:openpc:resource:${session.principalId}`,
    },
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
  const registered = Object.values(actions).find((entry) => entry.id === operation.actionIntentId);
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
  value: WorkItemView | NextResponse,
  status = 200,
) {
  if (!(await current(request, runtime, session))) return safeProblem('PC-AUTH-0005', request);
  return isResponse(value)
    ? value
    : NextResponse.json(workItemView.parse(value), { status, headers: noStore });
}
export async function readWorkItemWorkbench(request: NextRequest) {
  const authorized = await context(request);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const entries = [...request.nextUrl.searchParams];
  const query = workItemQuery.safeParse({ view: 'LIST', ...Object.fromEntries(entries) });
  if (new Set(entries.map(([key]) => key)).size !== entries.length || !query.success)
    return safeProblem('PC-DATA-6004', request);
  const input = query.data;
  if ('actorKey' in input && input.actorKey !== authorized.binding.actorKey)
    return safeProblem('PC-AUTH-0005', request);
  if (input.view === 'LIST') {
    const parameters = new URLSearchParams({ limit: input.limit, sort: input.sort });
    if (input.cursor) parameters.set('cursor', input.cursor);
    if (input.filter) parameters.set('filter', input.filter);
    const response = await fetchOwner(request, runtime, session, `work-items?${parameters}`);
    const page = await ownerJson(response, workItemPage, request);
    if (isResponse(page)) return finish(request, runtime, session, page);
    if (response?.status !== 200)
      return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
    if (
      page.items.length > Number(input.limit) ||
      page.items.some(
        (item) =>
          item.participantId !== `urn:openpc:participant:${session.participantId}` ||
          !item.workItemId.startsWith('urn:openpc:resource:') ||
          (item.assigneeRef !== null && !item.assigneeRef.startsWith('urn:openpc:resource:')),
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
      `work-items/${encodeURIComponent(input.workItemRef)}`,
    );
    const item = await ownerJson(response, workItemRecord, request);
    if (isResponse(item)) return finish(request, runtime, session, item);
    if (response?.status !== 200)
      return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
    const etag = `"${digest({ resourceId: input.workItemRef.slice(-36), revision: item.revision })}"`;
    if (
      item.workItemId !== input.workItemRef ||
      item.participantId !== `urn:openpc:participant:${session.participantId}` ||
      response?.headers.get('etag') !== etag
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    return finish(request, runtime, session, {
      ...authorized.binding,
      kind: 'DETAIL',
      workItem: item,
      etag,
    });
  }
  const response = await fetchOwner(request, runtime, session, `operations/${input.operationId}`);
  const operation = await ownerJson(response, workItemOperation, request);
  if (isResponse(operation)) return finish(request, runtime, session, operation);
  if (response?.status !== 200)
    return finish(request, runtime, session, safeProblem('PC-INTEGRATION-5001', request));
  if (!validOperation(operation) || operation.operationId !== input.operationId)
    return safeProblem('PC-INTEGRATION-5001', request);
  return finish(request, runtime, session, { ...authorized.binding, kind: 'OPERATION', operation });
}
export async function mutateWorkItemWorkbench(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const authorized = await context(request, true);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const parsed = workItemCommand.safeParse(await readPublicCommand(request, 8192));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data;
  if (input.actorKey !== authorized.binding.actorKey) return safeProblem('PC-AUTH-0005', request);
  const selected = actions[input.command];
  const envelope = {
    actionIntentId: selected.id,
    actionIntentDigest: selected.digest,
    reason: input.reason,
  };
  const body =
    input.command === 'CREATE'
      ? createWorkItemSchema.parse({
          ...envelope,
          participantId: `urn:openpc:participant:${session.participantId}`,
          kind: input.kind,
          resourceRef: input.resourceRef,
          assigneeRef: input.assigneeRef,
        })
      : input.command === 'UPDATE'
        ? updateWorkItemSchema.parse({
            ...envelope,
            expectedRevision: input.expectedRevision,
            replacementDigest: input.replacementDigest,
          })
        : (input.command === 'CLAIM' ? claimWorkItemSchema : completeWorkItemSchema).parse({
            ...envelope,
            targetRef: input.workItemRef,
            expectedRevision: input.expectedRevision,
            inputDigest: digest({
              actionIntentId: selected.id,
              targetRef: input.workItemRef,
              expectedRevision: input.expectedRevision,
              transition: input.command,
            }),
          });
  if (
    input.command !== 'CREATE' &&
    input.etag !==
      `"${digest({ resourceId: input.workItemRef.slice(-36), revision: input.expectedRevision })}"`
  )
    return safeProblem('PC-DATA-6007', request);
  const token = await csrf(runtime, session, selected.id).catch(() => undefined);
  if (!token || !(await current(request, runtime, session)))
    return safeProblem('PC-AUTH-0005', request);
  const key = `workbench-work-item-${input.requestKey}`;
  const response = await fetchOwner(
    request,
    runtime,
    session,
    input.command === 'CREATE'
      ? 'work-items'
      : `work-items/${encodeURIComponent(input.workItemRef)}${input.command === 'UPDATE' ? '' : `/${input.command.toLowerCase()}`}`,
    {
      method: input.command === 'UPDATE' ? 'PATCH' : 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'OpenPC-Action-Intent-Digest': selected.digest,
        'Idempotency-Key': key,
        ...(input.command !== 'CREATE' ? { 'If-Match': input.etag } : {}),
      },
      body: JSON.stringify(body),
    },
  );
  const operation = await ownerJson(response, workItemOperation, request);
  if (isResponse(operation)) return finish(request, runtime, session, operation);
  if (
    response?.status !== 202 ||
    !validOperation(operation) ||
    operation.actionIntentId !== selected.id ||
    operation.idempotencyKey !== key ||
    (input.command !== 'CREATE' && operation.resourceRef !== input.workItemRef)
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
