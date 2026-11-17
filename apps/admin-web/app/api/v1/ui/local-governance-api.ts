import { createHash } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
export { participantAction } from '../../../../lib/participant-action';
import {
  hasJsonContentType,
  responseIds,
  localOwnerFetch,
  safeProblem,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

export const participantId = '018f0000-0000-7000-8000-000000000101';
export const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
export const checkerPrincipalId = '018f0000-0000-7000-8000-000000000112';
export const principalCreateAction = {
  id: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
  digest: 'sha256:831ef2e7e3b05e92f8a950cfc4e8bdacb5463889654759aa1fd88c59da50513f',
} as const;
export const approvalCreateAction = {
  id: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  digest: 'sha256:c86183ee9e432405de0d145e007846fc9511a43bec274a055ad43b1ccbc207f9',
} as const;
export const approvalDecisionAction = {
  id: 'ACT-POLICY_APPROVE_REQUEST-V1',
  digest: 'sha256:460403d23ce1c8fb48362b045fb558200fb3ea7ab73469546730b067c1d63cd8',
} as const;
export const approvalUpdateAction = {
  id: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
  digest: 'sha256:dd2b80258905498007f0de87338d5044e8d7bb9b5d12d8336f28a67cdd9c2be9',
} as const;

export const digestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const uuidSchema = z.uuid();
export const timestampSchema = z.string().datetime();
export const urnSchema = z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u);

export const publicOperationSchema = z
  .object({
    operationId: uuidSchema,
    actionIntentId: z.string(),
    intentDigest: digestSchema,
    idempotencyKey: z.string(),
    resourceRef: urnSchema,
    revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
    state: z.enum(['ACCEPTED', 'SUCCEEDED']),
    truthState: z.literal('SUCCESS'),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();
export const approvalSchema = z
  .object({
    approvalRequestId: urnSchema,
    actionIntentId: z.string(),
    candidateDigest: digestSchema,
    state: z.enum(['REQUESTED', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED']),
    makerSubjectRef: urnSchema,
    checkerSubjectRef: urnSchema.nullable(),
    revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();
export const approvalPageSchema = z
  .object({
    items: z.array(approvalSchema).max(50),
    nextCursor: z.string().nullable(),
    total: z
      .string()
      .regex(/^(?:0|[1-9][0-9]*)$/u)
      .nullable(),
    completeness: z.enum(['COMPLETE', 'UNKNOWN']),
    authorizedEmpty: z.boolean(),
    snapshotRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  })
  .strict();

export function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

export function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

export function contextAdmitted(session: IdentitySession): boolean {
  return (
    z.uuid().safeParse(session.participantId).success &&
    session.contextMode === 'PARTICIPANT' &&
    z.uuid().safeParse(session.privacyDomainId).success &&
    typeof session.principalId === 'string'
  );
}

export function publicHeaders(runtime: LocalConfig, session: IdentitySession, ids = responseIds()) {
  return {
    'Cookie': `__Host-openpc_session=${session.sessionToken}`,
    'OpenPC-API-Version': '1',
    'OpenPC-Participant-ID': `urn:openpc:participant:${session.participantId}`,
    'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${session.privacyDomainId}`,
    'X-Request-ID': ids.requestId,
    'X-Correlation-ID': ids.correlationId,
    'Origin': new URL(runtime.publicApiUrl).origin,
  };
}

export async function csrf(
  runtime: LocalConfig,
  session: IdentitySession,
  actionIntentId: string,
  signal?: AbortSignal,
) {
  const response = await localOwnerFetch(`${runtime.publicApiUrl}/api/v1/session/csrf`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      'Cookie': `__Host-openpc_session=${session.sessionToken}`,
      'Content-Type': 'application/json',
      'Origin': new URL(runtime.publicApiUrl).origin,
    },
    body: JSON.stringify({ actionIntentId }),
    signal,
  }).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type'))) return undefined;
  const value = z
    .object({ csrfToken: z.string().min(32).max(256) })
    .strict()
    .safeParse(await response.json());
  return value.success ? value.data.csrfToken : undefined;
}

export function ownerFailure(response: Response | undefined, request: NextRequest) {
  if (!response) return safeProblem('PC-INTEGRATION-5001', request);
  if (response.status === 409) return safeProblem('PC-RUNTIME-3007', request);
  if (response.status === 412 || response.status === 428)
    return safeProblem('PC-DATA-6007', request);
  if (response.status === 400 || response.status === 422)
    return safeProblem('PC-DATA-6004', request);
  if ([401, 403, 404].includes(response.status)) return safeProblem('PC-AUTH-0005', request);
  return safeProblem('PC-INTEGRATION-5001', request);
}

export async function logOwnerFailure(stage: string, response: Response | undefined) {
  const body = response
    ? z
        .object({ code: z.string().max(80).optional(), error: z.unknown().optional() })
        .passthrough()
        .safeParse(
          await response
            .clone()
            .json()
            .catch(() => undefined),
        )
    : undefined;
  const nested = z
    .object({ code: z.string().max(80) })
    .passthrough()
    .safeParse(body?.success ? body.data.error : undefined);
  process.stderr.write(
    `OPENPC_PARTICIPANT_WORKBENCH_FAILURE|stage=${stage}|upstream_status=${response?.status ?? 0}|upstream_code=${body?.success ? (body.data.code ?? (nested.success ? nested.data.code : 'unclassified')) : 'unclassified'}\n`,
  );
}

type HandoffReadStage =
  | 'platform-handoff-approval'
  | 'platform-handoff-preparation'
  | 'platform-handoff-readiness'
  | 'platform-handoff-envelope'
  | 'transaction-approval'
  | 'transaction-candidate'
  | 'transaction-resource'
  | 'transaction-operation'
  | 'transaction-approvals';

function handoffReadFailure(
  stage: HandoffReadStage | undefined,
  response: Response | undefined,
  reason: 'transport' | 'response' | 'schema',
) {
  if (stage)
    process.stderr.write(
      JSON.stringify({
        event: stage.startsWith('transaction-')
          ? 'openpc.transaction.owner-read-failed'
          : 'openpc.platform-administrator.owner-read-failed',
        stage,
        reason,
        status: response?.status ?? null,
      }) + '\n',
    );
}

export async function ownerJson<T>(
  response: Response | undefined,
  schema: z.ZodType<T>,
  request: NextRequest,
  diagnosticStage?: HandoffReadStage,
) {
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type'))) {
    handoffReadFailure(diagnosticStage, response, response ? 'response' : 'transport');
    return ownerFailure(response, request);
  }
  const parsed = schema.safeParse(await response.json().catch(() => undefined));
  if (!parsed.success) handoffReadFailure(diagnosticStage, response, 'schema');
  return parsed.success ? parsed.data : safeProblem('PC-INTEGRATION-5001', request);
}

export function isResponse(value: unknown): value is NextResponse {
  return value instanceof Response;
}

export async function approval(
  runtime: LocalConfig,
  session: IdentitySession,
  id: string,
  request: NextRequest,
  diagnosticStage?: HandoffReadStage,
) {
  const urn = `urn:openpc:resource:${id}`;
  const response = await localOwnerFetch(
    `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(urn)}`,
    {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
      signal: request.signal,
    },
  ).catch(() => undefined);
  return ownerJson(response, approvalSchema, request, diagnosticStage);
}

export async function approveGovernanceRequest(
  runtime: LocalConfig,
  session: IdentitySession,
  approvalRequestId: string,
  request: NextRequest,
) {
  const noStoreHeaders = { 'Cache-Control': 'no-store' };
  const current = await approval(runtime, session, approvalRequestId, request);
  if (isResponse(current)) return current;
  if (
    current.checkerSubjectRef !== `urn:openpc:resource:${session.principalId}` ||
    current.makerSubjectRef === current.checkerSubjectRef
  )
    return safeProblem('PC-AUTH-0005', request);
  if (current.state === 'APPROVED')
    return NextResponse.json({ reconciled: true, approval: current }, { headers: noStoreHeaders });
  if (current.state !== 'REQUESTED') return safeProblem('PC-RUNTIME-3007', request);
  const inputDigest = digest({
    actionIntentId: approvalDecisionAction.id,
    approvalRequestId: current.approvalRequestId,
    candidateDigest: current.candidateDigest,
    expectedRevision: current.revision,
    decision: 'APPROVE',
  });
  if (request.signal.aborted) return safeProblem('PC-INTEGRATION-5001', request);
  const csrfToken = await csrf(runtime, session, approvalDecisionAction.id, request.signal);
  if (request.signal.aborted) return safeProblem('PC-INTEGRATION-5001', request);
  if (!csrfToken) return safeProblem('PC-AUTH-0005', request);
  const ids = responseIds(request);
  const ownerResponse = await localOwnerFetch(
    `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(current.approvalRequestId)}/approve`,
    {
      method: 'POST',
      cache: 'no-store',
      signal: request.signal,
      headers: {
        ...publicHeaders(runtime, session, ids),
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
        'Idempotency-Key': `workbench-approve-${approvalRequestId}`,
        'If-Match': `"${digest({ resourceId: approvalRequestId, revision: current.revision })}"`,
        'X-OpenPC-Action-Intent-Digest': approvalDecisionAction.digest,
        'OpenPC-Action-Intent-Digest': approvalDecisionAction.digest,
      },
      body: JSON.stringify({
        targetRef: current.approvalRequestId,
        actionIntentId: approvalDecisionAction.id,
        actionIntentDigest: approvalDecisionAction.digest,
        inputDigest,
        expectedRevision: current.revision,
        reason: 'Distinct checker approved the immutable Workbench candidate.',
      }),
    },
  ).catch(() => undefined);
  const operation = await ownerJson(ownerResponse, publicOperationSchema, request);
  if (isResponse(operation)) return operation;
  const readback = await approval(runtime, session, approvalRequestId, request);
  if (isResponse(readback) || readback.state !== 'APPROVED')
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(
    { operation, approval: readback },
    { status: 202, headers: noStoreHeaders },
  );
}
