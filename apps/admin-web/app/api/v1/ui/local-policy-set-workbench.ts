import { createHash } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { policySetResponseSchema } from '../../../../../../services/module-registry/src/policy-set-contract';
import {
  collectionResponseSchema,
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
import {
  csrf,
  isResponse,
  logOwnerFailure,
  ownerJson,
  publicHeaders,
} from './local-governance-api';

const noStore = { 'Cache-Control': 'no-store' };
export const policySetCreateAction = {
  id: 'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
  digest: `sha256:${createHash('sha256').update(['ACT-POLICY_SETS_CREATE_RESOURCE-V1', 'policy-sets', 'CREATE', 'STANDARD', 'false', 'false', 'true', 'AUTHORIZED_TYPE_ONLY', 'AUTHORIZED_MINIMAL', 'CREATE_POLICY_SETS'].join('\0')).digest('hex')}`,
};
const create = z.strictObject({
  requestKey: z.uuid(),
  name: z.string().min(1).max(160),
  reason: z.string().min(1).max(1024),
});
const query = z.strictObject({
  policySetId: z
    .string()
    .regex(
      /^urn:openpc:policy-set:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    )
    .optional(),
  cursor: z.string().min(1).max(2048).optional(),
});

export async function policySetCollection(
  runtime: LocalConfig,
  session: IdentitySession,
  request: NextRequest,
  cursor?: string,
) {
  const params = new URLSearchParams({ limit: '50', sort: '-updatedAt' });
  if (cursor) params.set('cursor', cursor);
  const response = await fetch(`${runtime.publicApiUrl}/api/v1/policy-sets?${params}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session),
  }).catch(() => undefined);
  if (!response?.ok) await logOwnerFailure('policy-set-collection', response);
  const result = await ownerJson(
    response,
    collectionResponseSchema(policySetResponseSchema),
    request,
  );
  if (isResponse(result)) return result;
  if (
    result.items.some(
      (item) => item.participantId !== `urn:openpc:participant:${session.participantId}`,
    )
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return result;
}

export async function readPolicySets(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  const session = runtime && (await authenticated(request, runtime));
  if (!runtime || !session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  const pairs = [...request.nextUrl.searchParams];
  const parsed = query.safeParse(Object.fromEntries(pairs));
  if (
    !parsed.success ||
    new Set(pairs.map(([key]) => key)).size !== pairs.length ||
    (parsed.data.policySetId && parsed.data.cursor)
  )
    return safeProblem('PC-DATA-6004', request);
  const result = parsed.data.policySetId
    ? await ownerJson(
        await fetch(
          `${runtime.publicApiUrl}/api/v1/policy-sets/${encodeURIComponent(parsed.data.policySetId)}`,
          { cache: 'no-store', headers: publicHeaders(runtime, session) },
        ).catch(() => undefined),
        policySetResponseSchema,
        request,
      )
    : await policySetCollection(runtime, session, request, parsed.data.cursor);
  if (isResponse(result)) return result;
  if (
    'policySetId' in result &&
    (result.participantId !== `urn:openpc:participant:${session.participantId}` ||
      result.policySetId !== parsed.data.policySetId)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(result, { headers: noStore });
}

export async function createPolicySet(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime || !sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  const parsed = create.safeParse(await readPublicCommand(request, 8192));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const token = await csrf(runtime, session, policySetCreateAction.id);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const key = `policy-set-${parsed.data.requestKey}`;
  const operation = await ownerJson(
    await fetch(`${runtime.publicApiUrl}/api/v1/policy-sets`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'Idempotency-Key': key,
        'X-OpenPC-Action-Intent-Digest': policySetCreateAction.digest,
      },
      body: JSON.stringify({
        participantId: `urn:openpc:participant:${session.participantId}`,
        name: parsed.data.name,
        activeVersionDigest: null,
        reason: parsed.data.reason,
        actionIntentId: policySetCreateAction.id,
        actionIntentDigest: policySetCreateAction.digest,
      }),
    }).catch(() => undefined),
    operationResponseSchema,
    request,
  );
  if (isResponse(operation)) return operation;
  if (
    operation.actionIntentId !== policySetCreateAction.id ||
    operation.intentDigest !== policySetCreateAction.digest ||
    operation.idempotencyKey !== key ||
    operation.state !== 'SUCCEEDED'
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json({ operation }, { status: 201, headers: noStore });
}
