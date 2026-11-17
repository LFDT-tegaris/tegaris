import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { enrollmentReadbackSchema } from '../../../../lib/authenticator-enrollment';

import {
  authenticated,
  functionalIdentitySession,
  encodeBffSession,
  hasJsonContentType,
  identityCsrf,
  identityOwnerHeaders,
  identitySessionToken,
  localRuntimeConfig,
  parsePublicCommand,
  safeProblem,
  sameOrigin,
  type IdentitySession,
  type LocalConfig,
  validateIdentitySessionToken,
} from './local-runtime';
import { functionalActorCookie, functionalContextCookie } from './functional-test-profile';

const sessionCookie = 'openpc_local_runtime_session';
const initialOptionsPath = '/api/v1/ui/webauthn/initial-registration/options';
const initialCompletePath = '/api/v1/ui/webauthn/initial-registration/complete';
const contextPath = '/api/v1/ui/session/context';
const base64Url = z.string().regex(/^[A-Za-z0-9_-]+$/u);
const positiveEpoch = z.string().regex(/^[1-9][0-9]*$/u);
const initialActionIntentId = 'ACT-IDENTITY_UPDATE_STEP_UP-V1';
const contextActionIntentId = 'ACT-IDENTITY_CREATE_SESSION-V1';
export const registrationResponseSchema = z
  .object({
    id: base64Url.min(1).max(2048),
    rawId: base64Url.min(1).max(2048),
    type: z.literal('public-key'),
    response: z
      .object({
        attestationObject: base64Url.min(1).max(65_536),
        clientDataJSON: base64Url.min(1).max(16_384),
        transports: z.array(z.string().min(1).max(64)).max(16),
      })
      .strict(),
    clientExtensionResults: z.record(z.string(), z.unknown()),
    authenticatorAttachment: z.enum(['cross-platform', 'platform']).nullable(),
  })
  .strict();
const initialCompleteSchema = z
  .object({
    enrollmentId: z.uuid(),
    response: registrationResponseSchema,
    expectedSessionId: z.uuid().optional(),
  })
  .strict();
export const registrationOptionsSchema = z
  .object({
    enrollmentId: z.uuid(),
    expiresAt: z.string().datetime(),
    publicKey: z
      .object({
        challenge: base64Url.min(32).max(256),
        rp: z.object({ id: z.string().min(1).max(255), name: z.string().min(1).max(255) }),
        user: z.object({
          id: base64Url.min(1).max(2048),
          name: z.string().min(1).max(512),
          displayName: z.string().min(1).max(512),
        }),
        pubKeyCredParams: z
          .array(z.object({ alg: z.number().int(), type: z.literal('public-key') }))
          .min(1)
          .max(32),
      })
      .passthrough(),
  })
  .strict();
const registeredCredentialSchema = z
  .object({
    credentialId: z.uuid(),
    externalCredentialId: base64Url.min(1).max(2048),
    credentialEpoch: positiveEpoch,
    state: z.literal('ACTIVE'),
  })
  .strict();
const contextInputSchema = z
  .object({
    participantId: z.uuid(),
    privacyDomainId: z.uuid(),
    expectedSessionId: z.uuid().optional(),
  })
  .strict();
const participantSessionSchema = z
  .object({
    sessionId: z.uuid(),
    sessionToken: z.string().regex(/^[0-9a-f-]{36}\.[0-9a-f-]{36}$/u),
    principalId: z.uuid(),
    participantId: z.uuid(),
    contextMode: z.literal('PARTICIPANT'),
    privacyDomainId: z.uuid(),
    contextEpoch: positiveEpoch,
    participantEpoch: positiveEpoch,
    authorityEpoch: positiveEpoch,
    sessionEpoch: positiveEpoch,
    refreshFamilyId: z.uuid(),
    state: z.literal('ACTIVE'),
    issuedAt: z.string().datetime(),
    lastSeenAt: z.string().datetime(),
    idleExpiresAt: z.string().datetime(),
    absoluteExpiresAt: z.string().datetime(),
    stepUpVerifiedAt: z.string().datetime(),
  })
  .strict();

function admitted(request: NextRequest, path: string): boolean {
  return (
    request.method === 'POST' &&
    request.nextUrl.pathname === path &&
    sameOrigin(request) &&
    hasJsonContentType(request.headers.get('content-type'))
  );
}

async function bootstrapOwnerFailure(stage: string, response: Response): Promise<void> {
  const code = z
    .object({ error: z.object({ code: z.string().max(80) }).passthrough() })
    .passthrough()
    .safeParse(
      await response
        .clone()
        .json()
        .catch(() => undefined),
    );
  process.stderr.write(
    `OPENPC_LOCAL_BOOTSTRAP_FAILURE|stage=${stage}|upstream_status=${response.status}|upstream_code=${code.success ? code.data.error.code : 'unclassified'}\n`,
  );
}

type OwnerContext =
  | { readonly runtime: LocalConfig; readonly failure: NextResponse }
  | {
      readonly runtime: LocalConfig;
      readonly session: IdentitySession;
      readonly csrfToken: string;
    };

async function ownerContext(
  request: NextRequest,
  path: string,
  actionIntentId: string,
): Promise<OwnerContext | undefined> {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) {
    process.stderr.write('OPENPC_LOCAL_BOOTSTRAP_FAILURE|stage=runtime-configuration\n');
    return undefined;
  }
  if (!admitted(request, path)) return { runtime, failure: safeProblem('PC-AUTH-0002', request) };
  const session = await authenticated(request, runtime);
  if (!session) {
    process.stderr.write('OPENPC_LOCAL_BOOTSTRAP_FAILURE|stage=session-validation\n');
    return { runtime, failure: safeProblem('PC-AUTH-0005', request) };
  }
  const csrfToken = await identityCsrf(runtime, session, actionIntentId);
  if (!csrfToken) {
    process.stderr.write('OPENPC_LOCAL_BOOTSTRAP_FAILURE|stage=csrf-issuance\n');
    return { runtime, failure: safeProblem('PC-AUTH-0005', request) };
  }
  return { runtime, session, csrfToken };
}

export async function beginInitialWebAuthnRegistration(request: NextRequest) {
  const context = await ownerContext(request, initialOptionsPath, initialActionIntentId);
  if (!context) return safeProblem('PC-AUTH-0005', request);
  if ('failure' in context) return context.failure;
  const input = z
    .object({ hardwareAttestation: z.boolean().optional(), expectedSessionId: z.uuid().optional() })
    .strict()
    .safeParse(parsePublicCommand(await request.text()));
  if (!input.success) return safeProblem('PC-DATA-6004', request);
  if (input.data.expectedSessionId && input.data.expectedSessionId !== context.session.sessionId)
    return safeProblem('PC-AUTH-0005', request);
  const browserOrigin = request.headers.get('origin')!;
  const identityResponse = await fetch(
    `${context.runtime.identityUrl}/v1/identity/webauthn/initial-registration/options`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...identityOwnerHeaders(context.runtime, context.session, browserOrigin),
        'X-CSRF-Token': context.csrfToken,
      },
      body: JSON.stringify({ hardwareAttestation: input.data.hardwareAttestation }),
    },
  ).catch(() => undefined);
  if (
    !identityResponse ||
    identityResponse.status !== 201 ||
    !hasJsonContentType(identityResponse.headers.get('content-type'))
  ) {
    if (identityResponse) await bootstrapOwnerFailure('registration-options', identityResponse);
    return safeProblem(identityResponse ? 'PC-AUTH-0006' : 'PC-INTEGRATION-5001', request);
  }
  const enrollment = registrationOptionsSchema.safeParse(await identityResponse.json());
  if (!enrollment.success || enrollment.data.publicKey.rp.id !== new URL(browserOrigin).hostname) {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
  return NextResponse.json(enrollment.data, {
    status: 201,
    headers: { 'Cache-Control': 'no-store' },
  });
}

export async function completeInitialWebAuthnRegistration(request: NextRequest) {
  const context = await ownerContext(request, initialCompletePath, initialActionIntentId);
  if (!context) return safeProblem('PC-AUTH-0005', request);
  if ('failure' in context) return context.failure;
  const input = initialCompleteSchema.safeParse(parsePublicCommand(await request.text()));
  if (!input.success) return safeProblem('PC-DATA-6004', request);
  if (input.data.expectedSessionId && input.data.expectedSessionId !== context.session.sessionId)
    return safeProblem('PC-AUTH-0005', request);
  const browserOrigin = request.headers.get('origin')!;
  const identityResponse = await fetch(
    `${context.runtime.identityUrl}/v1/identity/webauthn/initial-registration/complete`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...identityOwnerHeaders(context.runtime, context.session, browserOrigin),
        'X-CSRF-Token': context.csrfToken,
      },
      body: JSON.stringify({
        enrollmentId: input.data.enrollmentId,
        response: input.data.response,
      }),
    },
  ).catch(() => undefined);
  if (
    !identityResponse ||
    identityResponse.status !== 201 ||
    !hasJsonContentType(identityResponse.headers.get('content-type'))
  ) {
    if (identityResponse) await bootstrapOwnerFailure('registration-complete', identityResponse);
    return safeProblem(identityResponse ? 'PC-AUTH-0006' : 'PC-INTEGRATION-5001', request);
  }
  const credential = registeredCredentialSchema.safeParse(await identityResponse.json());
  if (!credential.success) return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(credential.data, {
    status: 201,
    headers: { 'Cache-Control': 'no-store' },
  });
}

export async function selectLocalParticipantContext(request: NextRequest) {
  const context = await ownerContext(request, contextPath, contextActionIntentId);
  if (!context) return safeProblem('PC-AUTH-0005', request);
  if ('failure' in context) return context.failure;
  const input = contextInputSchema.safeParse(parsePublicCommand(await request.text()));
  if (!input.success) return safeProblem('PC-DATA-6004', request);
  if (input.data.expectedSessionId && input.data.expectedSessionId !== context.session.sessionId)
    return safeProblem('PC-AUTH-0005', request);
  if (input.data.participantId !== context.session.participantId) {
    return safeProblem('PC-AUTH-0005', request);
  }
  if (context.runtime.functionalTest) {
    const selected = await functionalIdentitySession(
      context.runtime,
      context.session.role,
      'PARTICIPANT',
    );
    if (
      !selected ||
      selected.participantId !== input.data.participantId ||
      selected.privacyDomainId !== input.data.privacyDomainId
    )
      return safeProblem('PC-AUTH-0005', request);
    const response = NextResponse.json(
      {
        sessionId: selected.sessionId,
        participantId: selected.participantId,
        contextMode: selected.contextMode,
        privacyDomainId: selected.privacyDomainId,
        contextEpoch: selected.contextEpoch,
      },
      { status: 201, headers: { 'Cache-Control': 'no-store' } },
    );
    for (const [name, value] of [
      [functionalActorCookie, selected.role],
      [functionalContextCookie, 'PARTICIPANT'],
    ] as const)
      response.cookies.set(name, value, {
        httpOnly: true,
        secure: request.nextUrl.protocol === 'https:',
        sameSite: 'strict',
        path: '/',
      });
    return response;
  }
  const identityResponse = await fetch(`${context.runtime.identityUrl}/api/v1/session/context`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...identityOwnerHeaders(context.runtime, context.session),
      'X-CSRF-Token': context.csrfToken,
    },
    body: JSON.stringify({
      participantId: input.data.participantId,
      privacyDomainId: input.data.privacyDomainId,
    }),
  }).catch(() => undefined);
  if (
    !identityResponse ||
    identityResponse.status !== 201 ||
    !hasJsonContentType(identityResponse.headers.get('content-type'))
  ) {
    if (identityResponse) await bootstrapOwnerFailure('context-selection', identityResponse);
    return safeProblem(identityResponse ? 'PC-AUTH-0005' : 'PC-INTEGRATION-5001', request);
  }
  const selected = participantSessionSchema.safeParse(await identityResponse.json());
  const nextToken = identitySessionToken(identityResponse);
  if (
    !selected.success ||
    !nextToken ||
    selected.data.sessionToken !== nextToken ||
    selected.data.participantId !== input.data.participantId ||
    selected.data.privacyDomainId !== input.data.privacyDomainId
  ) {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
  const readback = await validateIdentitySessionToken(context.runtime, nextToken);
  if (
    !readback ||
    readback.role !== context.session.role ||
    readback.sessionId !== selected.data.sessionId ||
    readback.contextMode !== 'PARTICIPANT' ||
    readback.privacyDomainId !== input.data.privacyDomainId ||
    readback.contextEpoch !== selected.data.contextEpoch
  ) {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
  const response = NextResponse.json(
    {
      sessionId: readback.sessionId,
      participantId: readback.participantId,
      contextMode: readback.contextMode,
      privacyDomainId: readback.privacyDomainId,
      contextEpoch: readback.contextEpoch,
    },
    { status: 201, headers: { 'Cache-Control': 'no-store' } },
  );
  response.cookies.set(
    sessionCookie,
    encodeBffSession({ ...readback, sessionToken: nextToken }, context.runtime.cookieKey),
    {
      httpOnly: true,
      secure: request.nextUrl.protocol === 'https:',
      sameSite: 'strict',
      path: '/',
      maxAge: 12 * 60 * 60,
    },
  );
  return response;
}

export async function readLocalWebAuthnEnrollment(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  const query = z
    .strictObject({ enrollmentId: z.uuid() })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    request.method !== 'GET' ||
    request.nextUrl.pathname !== '/api/v1/ui/webauthn/enrollment' ||
    !query.success ||
    [...request.nextUrl.searchParams].length !== 1
  )
    return safeProblem('PC-DATA-6004', request);
  const response = await fetch(
    `${runtime.identityUrl}/v1/identity/webauthn/enrollments/${query.data.enrollmentId}`,
    {
      cache: 'no-store',
      headers: identityOwnerHeaders(runtime, session),
    },
  ).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type')))
    return safeProblem(response ? 'PC-AUTH-0005' : 'PC-INTEGRATION-5001', request);
  const readback = enrollmentReadbackSchema.safeParse(await response.json());
  if (
    !readback.success ||
    readback.data.enrollmentId !== query.data.enrollmentId ||
    readback.data.principalId !== session.principalId ||
    readback.data.participantId !== session.participantId
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(readback.data, { headers: { 'Cache-Control': 'no-store' } });
}
