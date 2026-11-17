import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  policySetRefSchema,
  policyVersionRefSchema,
  policyVersionResponseSchema,
} from '../../../../../../services/module-registry/src/policy-version-contract';
import { collectionResponseSchema } from '../../../../../../services/control-api/src/configuration/resource-contracts';
import {
  policyVersionCatalogueSchema,
  policyVersionSelectionSchema,
} from '../../../../lib/policy-version-catalogue';
import {
  authenticated,
  localRuntimeConfig,
  safeProblem,
  type IdentitySession,
} from './local-runtime';
import { isResponse, ownerJson, publicHeaders } from './local-governance-api';

const actor = (session: IdentitySession) => ({
  sessionId: session.sessionId,
  principalId: session.principalId,
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId!,
  contextEpoch: session.contextEpoch,
});
const same = (left: IdentitySession, right: IdentitySession) =>
  left.sessionToken === right.sessionToken &&
  (['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const).every(
    (field) => left[field] === right[field],
  );
const querySchema = z.union([
  z.strictObject({
    policySetId: policySetRefSchema,
    cursor: z.string().min(1).max(2048).optional(),
  }),
  z.strictObject({ policySetId: policySetRefSchema, policyVersionId: policyVersionRefSchema }),
]);

export async function readPolicyVersions(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  const pairs = [...request.nextUrl.searchParams];
  const parsed = querySchema.safeParse(Object.fromEntries(pairs));
  if (!parsed.success || new Set(pairs.map(([key]) => key)).size !== pairs.length)
    return safeProblem('PC-DATA-6004', request);
  const query = parsed.data;
  const params = new URLSearchParams({
    limit: '20',
    sort: '-updatedAt',
    filter: `policySetId:eq:${query.policySetId}`,
  });
  if ('cursor' in query && query.cursor) params.set('cursor', query.cursor);
  const path =
    'policyVersionId' in query
      ? `/api/v1/policy-versions/${encodeURIComponent(query.policyVersionId)}`
      : `/api/v1/policy-versions?${params}`;
  const response = await fetch(`${runtime.publicApiUrl}${path}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session),
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
  }).catch(() => undefined);
  let result:
    | ReturnType<typeof policyVersionCatalogueSchema.safeParse>
    | ReturnType<typeof policyVersionSelectionSchema.safeParse>;
  if ('policyVersionId' in query) {
    const version = await ownerJson(response, policyVersionResponseSchema, request);
    if (isResponse(version)) return version;
    if (
      version.policySetId !== query.policySetId ||
      version.policyVersionId !== query.policyVersionId
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    result = policyVersionSelectionSchema.safeParse({ actor: actor(session), version });
  } else {
    const page = await ownerJson(
      response,
      collectionResponseSchema(policyVersionResponseSchema),
      request,
    );
    if (isResponse(page)) return page;
    result = policyVersionCatalogueSchema.safeParse({
      ...page,
      actor: actor(session),
      policySetId: query.policySetId,
    });
  }
  if (!result.success) return safeProblem('PC-INTEGRATION-5001', request);
  const current = await authenticated(request, runtime);
  if (!current || current.contextMode !== 'PARTICIPANT' || !same(session, current))
    return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(result.data, { headers: { 'Cache-Control': 'no-store' } });
}
