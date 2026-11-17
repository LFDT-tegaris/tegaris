import { createHash } from 'node:crypto';

import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';

import { processSnapshotSchema, routes, type ProcessSnapshot } from '@openpc/ui-shell';
import { policySetResponseSchema } from '../../../../../../services/module-registry/src/policy-set-contract';
import { policySetCollection } from './local-policy-set-workbench';
import { isResponse, ownerJson, publicHeaders } from './local-governance-api';

import {
  authenticated,
  csrfToken,
  framedDigest,
  hasJsonContentType,
  localRuntimeConfig,
  parsePublicCommand,
  responseIds,
  rfc3339Micros,
  safeProblem,
  sameOrigin,
  validCsrf,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

const domain = 'policy-author-compose-simulate';
const policyId = '018f0000-0000-7000-8000-000000000920';
const policyRef = `urn:openpc:policy-set:${policyId}`;
const noStoreHeaders = { 'Cache-Control': 'no-store' } as const;
const uuidV7Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const versionIdSchema = z.string().uuid();
const timestampSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u);

interface ActionDefinition {
  readonly intent: 'create-version' | 'simulate';
  readonly actionIntentId:
    'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1' | 'ACT-POLICY_CREATE_SIMULATION-V1';
  readonly actionIntentDigest: string;
  readonly path: string;
}

function semanticDigest(
  actionIntentId: string,
  resourceType: string,
  operationClass: string,
  riskClass: string,
  makerCheckerRequired: boolean,
  stepUpRequired: boolean,
  idempotencyRequired: boolean,
  existenceDisclosure: string,
  payloadDisclosure: string,
  evidenceClass: string,
): string {
  const fields = [
    actionIntentId,
    resourceType,
    operationClass,
    riskClass,
    String(makerCheckerRequired),
    String(stepUpRequired),
    String(idempotencyRequired),
    existenceDisclosure,
    payloadDisclosure,
    evidenceClass,
  ];
  return `sha256:${createHash('sha256').update(fields.join('\0')).digest('hex')}`;
}

export const localPolicyActions = Object.freeze({
  createVersion: {
    intent: 'create-version',
    actionIntentId: 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
    actionIntentDigest: semanticDigest(
      'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
      'policy-version',
      'CREATE',
      'STANDARD',
      false,
      false,
      true,
      'AUTHORIZED_ONLY',
      'AUTHORIZED_FULL',
      'POLICY_MUTATION',
    ),
    path: `/api/v1/ui/process-domains/${domain}/actions/create-version`,
  },
  simulate: {
    intent: 'simulate',
    actionIntentId: 'ACT-POLICY_CREATE_SIMULATION-V1',
    actionIntentDigest: semanticDigest(
      'ACT-POLICY_CREATE_SIMULATION-V1',
      'policy',
      'CREATE',
      'STANDARD',
      false,
      false,
      true,
      'AUTHORIZED_ONLY',
      'AUTHORIZED_FULL',
      'POLICY_SIMULATION',
    ),
    path: `/api/v1/ui/process-domains/${domain}/actions/simulate`,
  },
} satisfies Record<string, ActionDefinition>);

const admittedVersionSchema = z
  .object({
    policySetId: z
      .string()
      .regex(
        /^urn:openpc:policy-set:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      )
      .optional(),
    semanticVersion: z.string().regex(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u),
    normalizedPolicyDigest: digestSchema,
    dependencyClosureDigest: digestSchema,
    reason: z.string().min(1).max(1024),
  })
  .strict();
const createVersionSchema = z.union([
  admittedVersionSchema,
  z.strictObject({
    policySetId: admittedVersionSchema.shape.policySetId,
    semanticVersion: admittedVersionSchema.shape.semanticVersion,
    semanticDocument: z.record(z.string(), z.unknown()),
    reason: admittedVersionSchema.shape.reason,
  }),
]);

const contractSimulationSchema = z
  .object({
    policyVersionId: versionIdSchema,
    contractMethodPolicyId: z.string().regex(uuidV7Pattern),
    method: z.enum(['eth_call', 'eth_sendRawTransaction']),
    workloadId: z
      .string()
      .regex(
        /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
    assignmentId: z.string().regex(uuidV7Pattern),
    calldata: z
      .string()
      .regex(/^0x[0-9a-f]{8}(?:[0-9a-f]{2})*$/u)
      .max(262_146),
  })
  .strict();

const simulationSchema = z.union([
  z.strictObject({
    policyVersionId: versionIdSchema,
    visibilityPolicyId: z.string().regex(uuidV7Pattern),
    purpose: z.string().min(1).max(256),
    dimensions: z
      .array(z.enum(['EXISTENCE', 'METADATA', 'PAYLOAD', 'EVIDENCE', 'EXPORT']))
      .min(1)
      .max(5),
    fields: z.array(z.string().min(1).max(256)).max(64),
  }),
  z.strictObject({
    policyVersionId: versionIdSchema,
    indexerProfileId: z.string().regex(uuidV7Pattern),
    projectionPlanId: z.string().regex(uuidV7Pattern),
    dataClass: z.enum([
      'EVENT_LOG',
      'STATE_CALL',
      'RECEIPT',
      'BLOCK_HEADER',
      'FULL_BLOCK_TRANSACTIONS',
    ]),
    rangeStart: z.string().regex(/^[1-9][0-9]{0,19}$/u),
    rangeEnd: z.string().regex(/^[1-9][0-9]{0,19}$/u),
    maximumResponseBytes: z
      .number()
      .int()
      .min(1)
      .max(16 * 1024 * 1024),
  }),
  contractSimulationSchema,
  z.strictObject({
    policyVersionId: versionIdSchema,
    deploymentPolicyId: z.string().regex(uuidV7Pattern),
    method: z.literal('eth_sendRawTransaction'),
    signedTransaction: z
      .string()
      .regex(/^0x(?:[0-9a-f]{2})+$/u)
      .max(262_146),
  }),
]);

const createOperationSchema = z
  .object({
    operationId: z.string().regex(uuidV7Pattern),
    actionIntentId: z.literal('ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1'),
    intentDigest: digestSchema,
    idempotencyKey: z.string().min(1).max(256),
    resourceRef: z
      .string()
      .regex(
        /^urn:openpc:policy-version:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
    revision: z.literal('1'),
    state: z.literal('ACCEPTED'),
    truthState: z.literal('SUCCESS'),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

function ownerHeaders(
  runtime: LocalConfig,
  session: IdentitySession,
  ids: { readonly requestId: string; readonly correlationId: string },
) {
  const publicOrigin = new URL(runtime.publicApiUrl).origin;
  const participantRef = `urn:openpc:participant:${session.participantId}`;
  const privacyDomainRef = `urn:openpc:privacy-domain:${session.privacyDomainId}`;
  return {
    'Cookie': `__Host-openpc_session=${session.sessionToken}`,
    'OpenPC-API-Version': '1',
    'OpenPC-Participant-ID': participantRef,
    'OpenPC-Privacy-Domain-ID': privacyDomainRef,
    'X-Request-ID': ids.requestId,
    'X-Correlation-ID': ids.correlationId,
    'Origin': publicOrigin,
  };
}

function bffResponseHeaders(ids: { readonly requestId: string; readonly correlationId: string }) {
  return {
    ...noStoreHeaders,
    'OpenPC-API-Version': '1',
    'RateLimit-Limit': '100',
    'RateLimit-Remaining': '99',
    'RateLimit-Reset': '60',
    'X-Request-ID': ids.requestId,
    'X-Correlation-ID': ids.correlationId,
  };
}

async function identityCsrf(
  runtime: LocalConfig,
  session: IdentitySession,
  actionIntentId: string,
): Promise<string | undefined> {
  const response = await fetch(`${runtime.publicApiUrl}/api/v1/session/csrf`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      'Cookie': `__Host-openpc_session=${session.sessionToken}`,
      'Content-Type': 'application/json',
      'Origin': new URL(runtime.publicApiUrl).origin,
    },
    body: JSON.stringify({ actionIntentId }),
  });
  if (!response.ok || !hasJsonContentType(response.headers.get('content-type'))) return undefined;
  const parsed = z
    .object({ csrfToken: z.string().min(32).max(256) })
    .strict()
    .safeParse(await response.json());
  return parsed.success ? parsed.data.csrfToken : undefined;
}

function mutationRequestValid(
  request: NextRequest,
  session: IdentitySession,
  runtime: LocalConfig,
  action: ActionDefinition,
): boolean {
  const participantRef = `urn:openpc:participant:${session.participantId}`;
  return (
    request.method === 'POST' &&
    request.nextUrl.pathname === action.path &&
    sameOrigin(request) &&
    hasJsonContentType(request.headers.get('content-type')) &&
    request.headers.get('openpc-api-version') === '1' &&
    request.headers.get('openpc-participant-id') === participantRef &&
    request.headers.get('openpc-action-intent-digest') === action.actionIntentDigest &&
    uuidV7Pattern.test(request.headers.get('x-request-id') ?? '') &&
    uuidV7Pattern.test(request.headers.get('x-correlation-id') ?? '') &&
    /^[A-Za-z0-9._~-]{16,128}$/u.test(request.headers.get('idempotency-key') ?? '') &&
    validCsrf(
      request.headers.get('x-csrf-token'),
      session.sessionToken,
      runtime.cookieKey,
      action.path,
      action.actionIntentDigest,
    )
  );
}

export async function localPolicyBootstrap(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  const action = request.nextUrl.searchParams.get('action');
  const definition = Object.values(localPolicyActions).find(
    (candidate) => candidate.intent === action,
  );
  const session = await authenticated(request, runtime);
  if (
    !definition ||
    !session ||
    session.contextMode !== 'PARTICIPANT' ||
    session.privacyDomainId === undefined
  )
    return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json(
    {
      actionIntentDigest: definition.actionIntentDigest,
      csrfToken: csrfToken(
        session.sessionToken,
        runtime.cookieKey,
        definition.path,
        definition.actionIntentDigest,
      ),
      path: definition.path,
    },
    { headers: noStoreHeaders },
  );
}

export async function localPolicySnapshot(request: NextRequest, requestedDomain: string) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime || ![domain, 'visibility-event-disclosure'].includes(requestedDomain))
    return undefined;
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || session.privacyDomainId === undefined)
    return safeProblem('PC-AUTH-0005', request);
  const participantRef = `urn:openpc:participant:${session.participantId}`;
  const privacyDomainRef = `urn:openpc:privacy-domain:${session.privacyDomainId}`;
  const ids = responseIds(request);
  if (
    request.headers.get('openpc-api-version') !== '1' ||
    request.headers.get('openpc-participant-id') !== participantRef ||
    !uuidV7Pattern.test(request.headers.get('x-request-id') ?? '') ||
    !uuidV7Pattern.test(request.headers.get('x-correlation-id') ?? '')
  )
    return safeProblem('PC-DATA-6004', request);
  const policySets = await policySetCollection(runtime, session, request);
  if (isResponse(policySets)) return policySets;
  const route = routes.find((candidate) => candidate.domain === requestedDomain);
  if (!route) return safeProblem('PC-INTEGRATION-5001', request);
  const now = rfc3339Micros();
  const scopeDigest = framedDigest('openpc:ui-authorized-scope:v1', [
    'PARTICIPANT',
    participantRef,
    privacyDomainRef,
  ]);
  const snapshot: ProcessSnapshot = processSnapshotSchema.parse({
    snapshotId: ids.requestId,
    routeId: route.id,
    processDomainId: route.processDomainId,
    contextDigest: framedDigest('openpc:ui-authority-context:v1', [
      route.id,
      route.processDomainId,
      participantRef,
      privacyDomainRef,
      session.principalId,
    ]),
    authorityGeneration: session.contextEpoch,
    policyGeneration: '0',
    truthState: 'SUCCESS',
    scope: {
      plane: 'PARTICIPANT',
      participantId: participantRef,
      privacyDomainId: privacyDomainRef,
    },
    freshness: { observedAt: now, state: 'CURRENT' },
    completeness: 'COMPLETE',
    items: policySets.items.map((item) => ({
      resourceRef: item.policySetId,
      truthState: 'SUCCESS',
      scopeDigest,
      observedAt: now,
    })),
    authorizedActions: Object.values(localPolicyActions).map((action) => ({
      actionIntentId: action.actionIntentId,
      actionIntentDigest: action.actionIntentDigest,
      operationId:
        action.intent === 'create-version' ? 'createPolicyVersion' : 'simulatePolicyVersion',
      method: 'POST',
      path: action.path,
      riskClass: 'STANDARD',
      stepUp: 'NONE',
      idempotency: 'KEY_UNTIL_TERMINAL',
      etagRequired: false,
    })),
    evidenceRefs: [],
    observedAt: now,
  });
  return NextResponse.json(snapshot, {
    headers: {
      ...noStoreHeaders,
      'ETag': `"${framedDigest('openpc:policy-author-snapshot:v1', [policyRef, session.principalId])}"`,
      'OpenPC-API-Version': '1',
      'RateLimit-Limit': '100',
      'RateLimit-Remaining': '99',
      'RateLimit-Reset': '60',
      'X-Request-ID': ids.requestId,
      'X-Correlation-ID': ids.correlationId,
    },
  });
}

export async function localPolicyAction(
  request: NextRequest,
  requestedDomain: string,
  intent: string,
) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime || requestedDomain !== domain) return undefined;
  const action = Object.values(localPolicyActions).find((candidate) => candidate.intent === intent);
  const session = await authenticated(request, runtime);
  if (
    !action ||
    !session ||
    session.contextMode !== 'PARTICIPANT' ||
    session.privacyDomainId === undefined
  )
    return safeProblem('PC-AUTH-0005', request);
  if (!mutationRequestValid(request, session, runtime, action))
    return safeProblem('PC-AUTH-0002', request);
  // Match the public policy owner's 1 MiB HTTP command limit. Individual
  // encoded call data and other fields retain their narrower schema limits.
  const raw = parsePublicCommand(await request.text(), 1_048_576);
  const ids = responseIds(request);
  try {
    if (action.intent === 'create-version') {
      const body = createVersionSchema.parse(raw);
      // Preserve the accepted original-context caller while new authoring sends
      // an explicitly selected public policy-set reference.
      const selectedPolicy =
        body.policySetId ??
        (session.participantId === '018f0000-0000-7000-8000-000000000101' &&
        session.privacyDomainId === '018f0000-0000-7000-8000-000000000201'
          ? policyRef
          : undefined);
      if (!selectedPolicy) return safeProblem('PC-DATA-6004', request);
      const ownerCsrf = await identityCsrf(runtime, session, action.actionIntentId);
      if (!ownerCsrf) {
        process.stderr.write('OPENPC_POLICY_BFF_FAILURE stage=identity-csrf\n');
        return safeProblem('PC-AUTH-0005', request);
      }
      const response = await fetch(`${runtime.publicApiUrl}/api/v1/policy-versions`, {
        method: 'POST',
        cache: 'no-store',
        headers: {
          ...ownerHeaders(runtime, session, ids),
          'Content-Type': 'application/json',
          'X-CSRF-Token': ownerCsrf,
          'Idempotency-Key': request.headers.get('idempotency-key') ?? '',
          'X-OpenPC-Action-Intent-Digest': action.actionIntentDigest,
        },
        body: JSON.stringify({
          ...body,
          policySetId: selectedPolicy,
          actionIntentId: action.actionIntentId,
          actionIntentDigest: action.actionIntentDigest,
        }),
      });
      if (!response.ok || !hasJsonContentType(response.headers.get('content-type'))) {
        process.stderr.write(
          `OPENPC_POLICY_BFF_FAILURE stage=create-version status=${response.status} content_type=${response.headers.get('content-type') ?? 'missing'}\n`,
        );
        return safeProblem(
          response.status === 409
            ? 'PC-RUNTIME-3007'
            : response.status === 400 || response.status === 422
              ? 'PC-DATA-6004'
              : response.status === 401 || response.status === 403 || response.status === 404
                ? 'PC-AUTH-0005'
                : 'PC-INTEGRATION-5001',
          request,
        );
      }
      const operation = createOperationSchema.safeParse(await response.json());
      const idempotencyKey = request.headers.get('idempotency-key');
      if (
        !operation.success ||
        operation.data.intentDigest !== action.actionIntentDigest ||
        operation.data.idempotencyKey !== idempotencyKey
      ) {
        process.stderr.write('OPENPC_POLICY_BFF_FAILURE stage=create-version-invalid-response\n');
        return safeProblem('PC-INTEGRATION-5001', request);
      }
      return NextResponse.json(operation.data, {
        status: 202,
        headers: bffResponseHeaders(ids),
      });
    }
    const body = simulationSchema.parse(raw);
    const participantRef = `urn:openpc:participant:${session.participantId}`;
    const privacyDomainRef = `urn:openpc:privacy-domain:${session.privacyDomainId}`;
    const response = await fetch(`${runtime.policyUrl}/internal/v1/policy-simulations`, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${runtime.policyToken}`,
        'Content-Type': 'application/json',
        'OpenPC-Participant-ID': participantRef,
        'OpenPC-Privacy-Domain-ID': privacyDomainRef,
        'X-Request-ID': ids.requestId,
      },
      body: JSON.stringify({
        sessionToken: session.sessionToken,
        policyVersionId: body.policyVersionId,
        request:
          'visibilityPolicyId' in body
            ? {
                visibilityPolicyId: body.visibilityPolicyId,
                purpose: body.purpose,
                dimensions: body.dimensions,
                fields: body.fields,
              }
            : 'indexerProfileId' in body
              ? {
                  indexerProfileId: body.indexerProfileId,
                  projectionPlanId: body.projectionPlanId,
                  dataClass: body.dataClass,
                  rangeStart: body.rangeStart,
                  rangeEnd: body.rangeEnd,
                  maximumResponseBytes: body.maximumResponseBytes,
                }
              : 'deploymentPolicyId' in body
                ? {
                    deploymentPolicyId: body.deploymentPolicyId,
                    method: body.method,
                    signedTransaction: body.signedTransaction,
                  }
                : {
                    contractMethodPolicyId: body.contractMethodPolicyId,
                    method: body.method,
                    workloadId: body.workloadId,
                    assignmentId: body.assignmentId,
                    calldata: body.calldata,
                  },
      }),
    });
    if (!response.ok || !hasJsonContentType(response.headers.get('content-type'))) {
      process.stderr.write(
        `OPENPC_POLICY_BFF_FAILURE stage=simulate status=${response.status} content_type=${response.headers.get('content-type') ?? 'missing'}\n`,
      );
      return safeProblem('PC-INTEGRATION-5001', request);
    }
    const result = z
      .object({
        simulationId: z.string().uuid(),
        policyVersionId: z.string().uuid(),
        authorityLabel: z.literal('SIMULATION_ONLY'),
        evaluation: z
          .object({ truthState: z.string(), permissions: z.array(z.string()) })
          .passthrough(),
        completedAt: z.string(),
      })
      .passthrough()
      .parse(await response.json());
    return NextResponse.json(result, { status: 201, headers: bffResponseHeaders(ids) });
  } catch {
    return safeProblem('PC-DATA-6004', request);
  }
}

/** Non-granting readback of the selected context's current policy generation. */
export async function localEffectiveAccess(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  const parameters = request.nextUrl.searchParams;
  const input = z
    .strictObject({
      policySetId: admittedVersionSchema.shape.policySetId,
      visibilityPolicyId: z.string().regex(uuidV7Pattern),
      purpose: z.string().min(1).max(256),
      dimensions: z.string().min(1).max(64),
      fields: z.string().max(16384),
    })
    .safeParse(Object.fromEntries(parameters));
  if (!input.success || [...parameters.keys()].length !== new Set(parameters.keys()).size)
    return safeProblem('PC-DATA-6004', request);
  const selectedPolicy =
    input.data.policySetId ??
    (session.participantId === '018f0000-0000-7000-8000-000000000101' &&
    session.privacyDomainId === '018f0000-0000-7000-8000-000000000201'
      ? policyRef
      : undefined);
  if (!selectedPolicy) return safeProblem('PC-DATA-6004', request);
  const parent = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/api/v1/policy-sets/${encodeURIComponent(selectedPolicy)}`,
      { cache: 'no-store', headers: publicHeaders(runtime, session) },
    ).catch(() => undefined),
    policySetResponseSchema,
    request,
  );
  if (isResponse(parent)) return parent;
  if (
    parent.policySetId !== selectedPolicy ||
    parent.participantId !== `urn:openpc:participant:${session.participantId}`
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  // Canonical JSON key order matches the public policy-set scope owner.
  const scopeDigest = `sha256:${createHash('sha256')
    .update(
      JSON.stringify({
        participantId: session.participantId,
        policySetId: selectedPolicy,
        privacyDomainId: session.privacyDomainId,
      }),
    )
    .digest('hex')}`;
  const ids = responseIds(request);
  try {
    const response = await fetch(
      `${runtime.publicApiUrl}/api/v1/effective-access?${new URLSearchParams({
        visibilityPolicyId: input.data.visibilityPolicyId,
        purpose: input.data.purpose,
        dimensions: input.data.dimensions,
        fields: input.data.fields,
        scopeDigest,
      })}`,
      { cache: 'no-store', headers: ownerHeaders(runtime, session, ids) },
    );
    if (response.status === 404)
      return NextResponse.json(
        { available: false, authoritative: false },
        { status: 404, headers: bffResponseHeaders(ids) },
      );
    if (!response.ok)
      return safeProblem(
        response.status === 401 || response.status === 403 ? 'PC-AUTH-0005' : 'PC-INTEGRATION-5001',
        request,
      );
    const result = z
      .strictObject({
        authoritative: z.literal(false),
        authorityGeneration: digestSchema,
        subjectRef: z.string().min(1).max(256),
        resourceRef: z.string().min(1).max(256),
        explanationRefs: z.array(z.string().min(1).max(256)).max(16),
        truthState: z.enum(['SUCCESS', 'DENIED', 'UNKNOWN']),
        effects: z.array(z.enum(['ALLOW', 'DENY'])).max(2),
      })
      .parse(await response.json());
    return NextResponse.json(result, { headers: bffResponseHeaders(ids) });
  } catch {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
}
