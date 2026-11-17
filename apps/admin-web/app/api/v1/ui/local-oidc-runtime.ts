import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { isWorkspaceReturnPath, signInHref } from '../../../../lib/workspace-navigation';
import {
  oidcProviderTransportMatches,
  validOidcProviderResponse,
} from '../../../../lib/oidc-provider-response';
import { completeInvitationProof, isInvitationProofCallback } from './local-invitation-proof';

import {
  encodeBffSession,
  hasJsonContentType,
  localRuntimeConfig,
  openBffPayload,
  parsePublicCommand,
  rfc3339Micros,
  localOwnerFetch,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

const oidcCustodyCookie = 'openpc_oidc_custody';
const bffSessionCookie = 'openpc_local_runtime_session';
const oidcCallbackPath = '/api/v1/ui/oidc-session/callback';
const oidcFailurePath = '/signin';
const maximumOidcAgeMs = 5 * 60 * 1000;
const noStoreHeaders = { 'Cache-Control': 'no-store' } as const;
const returnPathSchema = z.string().refine(isWorkspaceReturnPath);

const beginRequestSchema = z
  .object({
    returnPath: returnPathSchema,
    freshAuthentication: z.boolean().optional(),
    loginHint: z.string().trim().min(1).max(256).optional(),
    participantId: z.uuid().optional(),
  })
  .strict();
const identityAuthorizationSchema = z
  .object({
    durationProfile: z.literal('LOCAL_QA_10X').optional(),
    expiresAt: z.iso.datetime({ offset: true }).optional(),
    transactionId: z.uuid(),
    state: z.string().min(32).max(256),
    nonce: z.string().min(32).max(256),
    codeChallenge: z.string().regex(/^[A-Za-z0-9_-]{43,128}$/u),
    issuer: z.url(),
    clientId: z.string().min(1).max(256),
    redirectUri: z.url(),
  })
  .strict();
const custodySchema = z
  .object({
    transactionId: z.uuid(),
    identityCookie: z.string().regex(/^__Host-openpc_oidc=[A-Za-z0-9._-]+$/u),
    origin: z.url(),
    returnPath: returnPathSchema,
    issuedAt: z.number().int().nonnegative(),
    expiresAt: z.number().int().positive().optional(),
    durationProfile: z.literal('LOCAL_QA_10X').optional(),
    participantId: z.uuid().optional(),
    issuer: z.url().optional(),
  })
  .strict();
const identitySessionSchema = z
  .object({
    role: z.enum(['operator', 'viewer']),
    sessionId: z.uuid(),
    principalId: z.uuid(),
    participantId: z.uuid(),
    contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
    privacyDomainId: z.uuid().optional(),
    contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
    stepUpVerifiedAt: z.string().datetime().nullable(),
  })
  .strip();

function cookieValue(headers: Headers, name: string): string | undefined {
  const combined = headers.get('set-cookie');
  if (!combined) return undefined;
  const match = new RegExp(`(?:^|[,\\s])(${name}=[A-Za-z0-9._-]+)`, 'u').exec(combined);
  return match?.[1];
}

function clearOidcCustody(response: NextResponse, request: NextRequest) {
  response.cookies.set(oidcCustodyCookie, '', {
    httpOnly: true,
    secure: request.nextUrl.protocol === 'https:',
    sameSite: 'lax',
    path: oidcCallbackPath,
    maxAge: 0,
  });
}

function oidcFailure(request: NextRequest, custody?: z.infer<typeof custodySchema>) {
  let destination = new URL(oidcFailurePath, request.nextUrl.origin);
  if (custody) {
    destination = new URL(signInHref(custody.returnPath), custody.origin);
  }
  destination.searchParams.set('oidcError', 'authentication_failed');
  const response = NextResponse.redirect(destination, { headers: noStoreHeaders });
  clearOidcCustody(response, request);
  return response;
}

async function validateIdentitySession(
  runtime: LocalConfig,
  sessionToken: string,
): Promise<IdentitySession | undefined> {
  const response = await localOwnerFetch(
    `${runtime.identityUrl}/internal/v1/local/session/validate`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${runtime.identityToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ sessionToken }),
    },
  ).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type'))) return undefined;
  const parsed = identitySessionSchema.safeParse(await response.json());
  return parsed.success ? { ...parsed.data, sessionToken } : undefined;
}

export async function beginLocalOidc(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (
    !sameOrigin(request) ||
    !hasJsonContentType(request.headers.get('content-type')) ||
    request.nextUrl.pathname !== '/api/v1/ui/oidc-session'
  ) {
    return safeProblem('PC-AUTH-0002', request);
  }
  const body = beginRequestSchema.safeParse(parsePublicCommand(await request.text()));
  if (!body.success) return safeProblem('PC-DATA-6004', request);
  const participantId = body.data.participantId ?? runtime.oidcParticipantId;
  const identityResponse = await localOwnerFetch(`${runtime.identityUrl}/v1/identity/oidc/begin`, {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(participantId === undefined ? {} : { participantId }),
  }).catch(() => undefined);
  if (!identityResponse?.ok || !hasJsonContentType(identityResponse.headers.get('content-type'))) {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
  const authorization = identityAuthorizationSchema.safeParse(await identityResponse.json());
  const identityCookie = cookieValue(identityResponse.headers, '__Host-openpc_oidc');
  if (
    !authorization.success ||
    !identityCookie ||
    !oidcProviderTransportMatches(runtime.oidcAuthorizationUrl, authorization.data.issuer)
  ) {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
  const issuedAt = Date.now();
  const expiresAt =
    authorization.data.expiresAt === undefined
      ? issuedAt + maximumOidcAgeMs
      : Date.parse(authorization.data.expiresAt);
  if (
    (authorization.data.durationProfile !== undefined &&
      authorization.data.expiresAt === undefined) ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= issuedAt ||
    expiresAt >
      issuedAt + (authorization.data.durationProfile ? maximumOidcAgeMs * 10 : maximumOidcAgeMs)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const authorizationUri = new URL(runtime.oidcAuthorizationUrl);
  authorizationUri.search = new URLSearchParams({
    response_type: 'code',
    scope: 'openid',
    client_id: authorization.data.clientId,
    redirect_uri: authorization.data.redirectUri,
    state: authorization.data.state,
    nonce: authorization.data.nonce,
    code_challenge: authorization.data.codeChallenge,
    code_challenge_method: 'S256',
    ...(body.data.loginHint === undefined ? {} : { login_hint: body.data.loginHint }),
    ...(body.data.freshAuthentication === true ? { max_age: '0', prompt: 'login' } : {}),
  }).toString();
  const response = NextResponse.json(
    {
      authorizationUri: authorizationUri.href,
      state: authorization.data.state,
      expiresAt: rfc3339Micros(expiresAt),
    },
    { headers: noStoreHeaders },
  );
  response.cookies.set(
    oidcCustodyCookie,
    sealBffPayload(
      {
        transactionId: authorization.data.transactionId,
        identityCookie,
        origin: request.headers.get('origin'),
        returnPath: body.data.returnPath,
        issuedAt,
        issuer: authorization.data.issuer,
        ...(authorization.data.expiresAt !== undefined ? { expiresAt } : {}),
        ...(authorization.data.durationProfile
          ? { durationProfile: authorization.data.durationProfile }
          : {}),
        ...(participantId === undefined ? {} : { participantId }),
      },
      runtime.cookieKey,
      'oidc-custody',
    ),
    {
      httpOnly: true,
      secure: request.nextUrl.protocol === 'https:',
      sameSite: 'lax',
      path: oidcCallbackPath,
      maxAge: Math.floor((expiresAt - issuedAt) / 1000),
    },
  );
  return response;
}

export async function completeLocalOidc(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return oidcFailure(request);
  if (isInvitationProofCallback(request, runtime)) return completeInvitationProof(request, runtime);
  const code = request.nextUrl.searchParams.get('code');
  const state = request.nextUrl.searchParams.get('state');
  const custody = custodySchema.safeParse(
    openBffPayload(
      request.cookies.get(oidcCustodyCookie)?.value,
      runtime.cookieKey,
      'oidc-custody',
    ),
  );
  if (
    request.nextUrl.pathname !== oidcCallbackPath ||
    !validOidcProviderResponse(
      request.nextUrl.searchParams,
      custody.success ? custody.data.issuer : undefined,
      4096,
    ) ||
    !code ||
    code.length > 4096 ||
    !state ||
    state.length < 32 ||
    state.length > 256 ||
    !custody.success ||
    custody.data.issuedAt > Date.now() ||
    Date.now() >= (custody.data.expiresAt ?? custody.data.issuedAt + maximumOidcAgeMs) ||
    (custody.data.durationProfile !== undefined && custody.data.expiresAt === undefined) ||
    (custody.data.expiresAt ?? 0) >
      custody.data.issuedAt +
        (custody.data.durationProfile ? maximumOidcAgeMs * 10 : maximumOidcAgeMs)
  ) {
    return oidcFailure(request, custody.success ? custody.data : undefined);
  }
  const identityResponse = await localOwnerFetch(
    `${runtime.identityUrl}/v1/identity/oidc/callback`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Cookie': custody.data.identityCookie,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        transactionId: custody.data.transactionId,
        state,
        authorizationCode: code,
      }),
    },
  ).catch(() => undefined);
  const rawSessionCookie = identityResponse
    ? cookieValue(identityResponse.headers, '__Host-openpc_session')
    : undefined;
  const sessionToken = rawSessionCookie?.slice('__Host-openpc_session='.length);
  if (!identityResponse || identityResponse.status !== 201 || !sessionToken) {
    return oidcFailure(request, custody.data);
  }
  const session = await validateIdentitySession(runtime, sessionToken);
  if (
    !session ||
    session.stepUpVerifiedAt !== null ||
    (custody.data.participantId !== undefined &&
      session.participantId !== custody.data.participantId)
  ) {
    return oidcFailure(request, custody.data);
  }
  const destination = new URL(custody.data.returnPath, custody.data.origin);
  if (destination.origin !== custody.data.origin) return oidcFailure(request, custody.data);
  const response = NextResponse.redirect(destination, { headers: noStoreHeaders });
  response.cookies.set(bffSessionCookie, encodeBffSession(session, runtime.cookieKey), {
    httpOnly: true,
    secure: request.nextUrl.protocol === 'https:',
    sameSite: 'strict',
    path: '/',
    maxAge: 12 * 60 * 60,
  });
  clearOidcCustody(response, request);
  return response;
}
