import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  factArtifactResponseSchema,
  factArtifactOperationSchema,
  factArtifactUpdateSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';
import {
  collectionResponseSchema,
  indexerProfileResponseSchema,
  projectionPlanResponseSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';
import {
  authenticated,
  localRuntimeConfig,
  readPublicCommand,
  safeProblem,
  sameOrigin,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { csrf, isResponse, ownerJson, publicHeaders } from './local-governance-api';

const noStore = { 'Cache-Control': 'no-store' };
const resource = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const etag = z.string().regex(/^"sha256:[0-9a-f]{64}"$/u);
const page = collectionResponseSchema(factArtifactResponseSchema);
export const factActorSchema = z.strictObject({
  sessionId: z.uuidv7(),
  principalId: z.uuidv7(),
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  contextEpoch: z.string().regex(/^[0-9]+$/u),
});
const actor = (session: IdentitySession) =>
  factActorSchema.parse({
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextEpoch: session.contextEpoch,
  });
const input = z.strictObject({
  actor: factActorSchema,
  resourceRef: resource,
  etag,
  idempotencyKey: z.string().regex(/^[A-Za-z0-9._~-]{16,128}$/u),
  body: factArtifactUpdateSchema,
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

async function read<T>(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
) {
  const response = await fetch(`${runtime.publicApiUrl}/api/v1/${path}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session),
    signal: AbortSignal.timeout(15_000),
  }).catch(() => undefined);
  const value = await ownerJson(response, schema, request);
  if (isResponse(value)) return value;
  return { value, etag: response?.headers.get('etag') ?? null };
}

export async function readFactWorkbench(request: NextRequest) {
  const authorized = await context(request);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const query = z
    .strictObject({
      resourceRef: resource.optional(),
      operationId: z.uuidv7().optional(),
      cursor: z.string().min(1).max(8192).optional(),
      sourceCursor: z.string().min(1).max(8192).optional(),
      projectionCursor: z.string().min(1).max(8192).optional(),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams.keys()].length !== Object.keys(query.data).length
  )
    return safeProblem('PC-DATA-6004', request);
  const selected = query.data.resourceRef
    ? await read(
        request,
        runtime,
        session,
        `fact-artifacts/${encodeURIComponent(query.data.resourceRef)}`,
        factArtifactResponseSchema,
      )
    : null;
  if (isResponse(selected)) return selected;
  if (
    selected &&
    (!etag.safeParse(selected.etag).success ||
      selected.value.factArtifactId !== query.data.resourceRef)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const operation = query.data.operationId
    ? await read(
        request,
        runtime,
        session,
        `operations/${query.data.operationId}`,
        factArtifactOperationSchema,
      )
    : null;
  if (isResponse(operation)) return operation;
  if (
    operation &&
    (operation.value.operationId !== query.data.operationId ||
      operation.value.actionIntentId !== 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1')
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const artifacts = await read(
    request,
    runtime,
    session,
    `fact-artifacts?limit=50${query.data.cursor ? `&cursor=${encodeURIComponent(query.data.cursor)}` : ''}`,
    page,
  );
  if (isResponse(artifacts)) return artifacts;
  if (
    [...artifacts.value.items, ...(selected ? [selected.value] : [])].some(
      (item) =>
        item.participantId !== `urn:openpc:participant:${session.participantId}` ||
        item.privacyDomainId !== `urn:openpc:privacy-domain:${session.privacyDomainId}`,
    )
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const sources = await read(
    request,
    runtime,
    session,
    `indexer-profiles?limit=50${query.data.sourceCursor ? `&cursor=${encodeURIComponent(query.data.sourceCursor)}` : ''}`,
    collectionResponseSchema(indexerProfileResponseSchema),
  );
  if (isResponse(sources)) return sources;
  if (
    sources.value.items.some(
      (item) => item.participantId !== `urn:openpc:participant:${session.participantId}`,
    )
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const projections = await read(
    request,
    runtime,
    session,
    `projection-plans?limit=50${query.data.projectionCursor ? `&cursor=${encodeURIComponent(query.data.projectionCursor)}` : ''}`,
    collectionResponseSchema(projectionPlanResponseSchema),
  );
  if (isResponse(projections)) return projections;
  const current = await authenticated(request, runtime);
  if (
    !current ||
    current.contextMode !== 'PARTICIPANT' ||
    !current.privacyDomainId ||
    JSON.stringify(actor(current)) !== JSON.stringify(actor(session))
  )
    return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(
    {
      actor: actor(session),
      artifacts: artifacts.value,
      sources: sources.value,
      projections: projections.value,
      selected: selected ? { artifact: selected.value, etag: selected.etag } : null,
      operation: operation?.value ?? null,
    },
    { headers: noStore },
  );
}

export async function mutateFactWorkbench(request: NextRequest) {
  const authorized = await context(request, true);
  if (isResponse(authorized)) return authorized;
  const { runtime, session } = authorized;
  const stepUp = session.stepUpVerifiedAt ? Date.parse(session.stepUpVerifiedAt) : NaN;
  if (!Number.isFinite(stepUp) || stepUp > Date.now() || Date.now() - stepUp > 300_000)
    return safeProblem('PC-AUTH-0003', request);
  const command = input.safeParse(await readPublicCommand(request));
  if (!command.success) return safeProblem('PC-DATA-6004', request);
  if (JSON.stringify(command.data.actor) !== JSON.stringify(actor(session)))
    return safeProblem('PC-AUTH-0005', request);
  const { body, resourceRef, idempotencyKey, etag: match } = command.data;
  const token = await csrf(runtime, session, body.actionIntentId);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/fact-artifacts/${encodeURIComponent(resourceRef)}`,
    {
      method: 'PATCH',
      cache: 'no-store',
      signal: AbortSignal.timeout(30_000),
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'OpenPC-Action-Intent-Digest': body.actionIntentDigest,
        'Idempotency-Key': idempotencyKey,
        'If-Match': match,
      },
      body: JSON.stringify(body),
    },
  ).catch(() => undefined);
  const operation = await ownerJson(response, factArtifactOperationSchema, request);
  if (isResponse(operation)) return operation;
  if (
    response?.status !== 202 ||
    operation.resourceRef !== resourceRef ||
    operation.actionIntentId !== body.actionIntentId ||
    operation.intentDigest !== body.actionIntentDigest ||
    operation.idempotencyKey !== idempotencyKey
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(operation, { status: 202, headers: noStore });
}

export type FactArtifact = z.infer<typeof factArtifactResponseSchema>;
export type FactOperation = z.infer<typeof factArtifactOperationSchema>;
export type FactSource = z.infer<typeof indexerProfileResponseSchema>;
export type FactProjection = z.infer<typeof projectionPlanResponseSchema>;
