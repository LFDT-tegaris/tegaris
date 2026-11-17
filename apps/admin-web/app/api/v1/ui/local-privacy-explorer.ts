import { randomUUID } from 'node:crypto';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { createPrivacyExplorerClient } from '../../../../../../packages/api-client/src/privacy-explorer';
import { explorerProfileResponseSchema } from '../../../../../../services/control-api/src/configuration/privacy-explorer/profile-contract';
import {
  assertExplorerProjectionRequest,
  assertPrivacyExplorerOccurrence,
  type PrivacyExplorerResultV1,
  type PrivacyExplorerOccurrenceV1,
} from '../../../../../../services/control-api/src/contracts/privacy-explorer-adapter';
import {
  authenticated,
  localRuntimeConfig,
  readPublicCommand,
  safeProblem,
  sameOrigin,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import {
  canonicalJson,
  digest,
  isResponse,
  ownerJson,
  publicHeaders,
} from './local-governance-api';

const noStore = { 'Cache-Control': 'no-store' };
const resource = z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u);
const operationId = 'PXI-READ-GOVERNED-PROJECTION/v1';
const actor = (session: IdentitySession) => ({
  principalId: session.principalId,
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId!,
});
const actorKey = (session: IdentitySession) => {
  const { sessionToken, stepUpVerifiedAt, ...context } = session;
  void sessionToken;
  void stepUpVerifiedAt;
  return digest(context);
};
const inputSchema = z.strictObject({
  actorKey: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  profileRef: resource,
  purpose: z.string().min(1).max(256),
  dataClassId: z.string().min(1).max(256),
  projectionFields: z
    .array(z.string().regex(/^PEF-[A-Z0-9-]{1,64}$/u))
    .min(1)
    .max(64),
  filters: z
    .array(
      z.strictObject({
        fieldId: z.string().regex(/^PEF-[A-Z0-9-]{1,64}$/u),
        filterId: z.string().regex(/^PEFILTER-[A-Z0-9-]{1,64}$/u),
        value: z.union([z.string().max(256), z.number().int().safe(), z.boolean(), z.null()]),
      }),
    )
    .max(32),
  limit: z.number().int().min(1).max(1000),
  cursor: z
    .string()
    .regex(/^pec1\.[A-Za-z0-9_-]{43}$/u)
    .nullable(),
  occurrenceId: z.uuid(),
});
export type ExplorerIntent = z.infer<typeof inputSchema>;
export type ExplorerProfile = z.infer<typeof explorerProfileResponseSchema>;
export type ExplorerView = {
  actor: ReturnType<typeof actor>;
  actorKey: string;
  profile: ExplorerProfile | null;
};
export type ExplorerRead = {
  actorKey: string;
  occurrenceId: string;
  result: PrivacyExplorerResultV1;
};
export type ExplorerStatus = { actorKey: string; occurrence: PrivacyExplorerOccurrenceV1 };

async function context(request: NextRequest, post = false) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  if (post && !sameOrigin(request)) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  return { runtime, session };
}
async function sameActor(request: NextRequest, runtime: LocalConfig, session: IdentitySession) {
  const current = await authenticated(request, runtime);
  return (
    !!current && current.contextMode === 'PARTICIPANT' && actorKey(current) === actorKey(session)
  );
}
async function readOwner<T>(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
) {
  const response = await fetch(`${runtime.publicApiUrl}${path}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session),
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]),
  }).catch(() => undefined);
  return ownerJson(response, schema, request);
}

export async function readExplorerWorkbench(request: NextRequest) {
  const authorized = await context(request);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const query = z
    .strictObject({
      profileRef: resource.optional(),
      occurrenceId: z.uuid().optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams].length !== Object.keys(query.data).length ||
    (query.data.profileRef && query.data.occurrenceId)
  )
    return safeProblem('PC-DATA-6004', request);
  if (query.data.occurrenceId) {
    const status = await readOwner(
      request,
      runtime,
      session,
      `/v1/privacy-explorer/occurrences/${query.data.occurrenceId}`,
      z.unknown().transform((value, ctx) => {
        try {
          return assertPrivacyExplorerOccurrence(value);
        } catch {
          ctx.addIssue({ code: 'custom', message: 'Invalid occurrence' });
          return z.NEVER;
        }
      }),
    );
    if (isResponse(status)) return status;
    if (
      status.occurrenceId !== query.data.occurrenceId ||
      !(await sameActor(request, runtime, session))
    )
      return safeProblem('PC-AUTH-0005', request);
    return NextResponse.json(
      { actorKey: actorKey(session), occurrence: status },
      { headers: noStore },
    );
  }
  const profile = query.data.profileRef
    ? await readOwner(
        request,
        runtime,
        session,
        `/api/v1/privacy-explorer-profiles/${encodeURIComponent(query.data.profileRef)}`,
        explorerProfileResponseSchema,
      )
    : null;
  if (isResponse(profile)) return profile;
  if (profile && profile.registrationId !== query.data.profileRef)
    return safeProblem('PC-AUTH-0005', request);
  if (!(await sameActor(request, runtime, session))) return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(
    { actor: actor(session), actorKey: actorKey(session), profile },
    { headers: noStore },
  );
}

/** Browser intent is narrowed with the current public profile and authenticated context. */
export async function readExplorerProjection(request: NextRequest) {
  const authorized = await context(request, true);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const parsed = inputSchema.safeParse(await readPublicCommand(request, 65_536));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data;
  if (input.actorKey !== actorKey(session)) return safeProblem('PC-AUTH-0005', request);
  const registered = await readOwner(
    request,
    runtime,
    session,
    `/api/v1/privacy-explorer-profiles/${encodeURIComponent(input.profileRef)}`,
    explorerProfileResponseSchema,
  );
  if (isResponse(registered)) return registered;
  const profile = registered.profile;
  const source = profile.sourceBinding;
  if (
    registered.registrationId !== input.profileRef ||
    registered.state !== 'REGISTERED' ||
    !source
  )
    return safeProblem('PC-AUTH-0005', request);
  try {
    const requestScope = {
      participantId: session.participantId,
      privacyDomainId: session.privacyDomainId!,
      platformId: source.platformId,
      workloadId: source.workloadId,
      action: 'read',
    };
    const projectionFields = [...input.projectionFields].sort();
    const filters = [...input.filters].sort((a, b) =>
      a.fieldId < b.fieldId
        ? -1
        : a.fieldId > b.fieldId
          ? 1
          : a.filterId < b.filterId
            ? -1
            : a.filterId > b.filterId
              ? 1
              : canonicalJson(a.value) < canonicalJson(b.value)
                ? -1
                : canonicalJson(a.value) > canonicalJson(b.value)
                  ? 1
                  : 0,
    );
    const purpose = input.purpose;
    const subject = `urn:openpc:principal:${session.principalId}`;
    const query = {
      purpose,
      subject,
      resource: input.profileRef,
      action: 'read',
      scope: requestScope,
      operationId,
      semanticOperationVersion: '1.0.0',
      dataClassId: input.dataClassId,
      filters,
      page: { limit: input.limit },
      projectionFields,
      exportProfileDigest: profile.digest,
    };
    const body = assertExplorerProjectionRequest({
      operationVersion: 'v1',
      schemaVersion: '1.0',
      issuedAt: new Date().toISOString(),
      purpose,
      subject,
      resource: input.profileRef,
      action: 'read',
      scope: requestScope,
      operationId,
      semanticOperationVersion: '1.0.0',
      dataClassId: input.dataClassId,
      filters,
      page: { limit: input.limit, cursor: input.cursor },
      projectionFields,
      exportProfile: profile,
      queryDigest: digest(query),
      occurrence: { requestId: input.occurrenceId, correlationId: randomUUID() },
    });
    const client = createPrivacyExplorerClient({
      baseUrl: runtime.publicApiUrl,
      headers: publicHeaders(runtime, session),
      fetch: (target, init) =>
        fetch(target, {
          ...init,
          cache: 'no-store',
          signal: AbortSignal.any([request.signal, AbortSignal.timeout(40_000)]),
        }),
    });
    const result = await client.read(body);
    if (!(await sameActor(request, runtime, session))) return safeProblem('PC-AUTH-0005', request);
    if (result.problem)
      return NextResponse.json(result.problem, {
        status: result.problem.httpStatus,
        headers: noStore,
      });
    return NextResponse.json(
      { actorKey: actorKey(session), occurrenceId: input.occurrenceId, result: result.data },
      { headers: noStore },
    );
  } catch {
    // Ambiguous transport never retries a protected read. The occurrence can be queried separately.
    return safeProblem('PC-INTEGRATION-5001', request);
  }
}
