import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  oidcProviderTransportMatches,
  validOidcProviderResponse,
} from '../../../../lib/oidc-provider-response';
import { invitationAcceptance, invitationProofInput } from '../../../../lib/invitation-workflow';
import {
  hasJsonContentType,
  localRuntimeConfig,
  openBffPayload,
  parsePublicCommand,
  safeProblem,
  sameOrigin,
  sealBffPayload,
  type LocalConfig,
} from './local-runtime';
const cookieName = 'openpc_invitation_custody',
  resultCookie = 'openpc_invitation_result';
const callbackPath = '/api/v1/ui/oidc-session/callback';
const noStore = { 'Cache-Control': 'no-store' };
const age = 300_000;
const bootstrapAge = 7 * 24 * 60 * 60 * 1000;
const privateAcceptance = invitationAcceptance.extend({
  bootstrap: z
    .strictObject({
      mandateId: z.uuid(),
      sessionToken: z.string().regex(/^[0-9a-f-]{36}\.[0-9a-f-]{36}$/u),
      state: z.literal('CLAIM_PENDING'),
    })
    .optional(),
});
export function invitationBootstrapCustody(request: NextRequest, runtime: LocalConfig) {
  const parsed = z
    .strictObject({ acceptance: privateAcceptance, issuedAt: z.number().int().nonnegative() })
    .safeParse(
      openBffPayload(
        request.cookies.get(resultCookie)?.value,
        runtime.cookieKey,
        'invitation-result',
      ),
    );
  if (
    !parsed.success ||
    parsed.data.issuedAt > Date.now() ||
    Date.now() - parsed.data.issuedAt >= (parsed.data.acceptance.bootstrap ? bootstrapAge : age)
  )
    return undefined;
  return parsed.data.acceptance;
}
const authorizationSchema = z.strictObject({
  durationProfile: z.literal('LOCAL_QA_10X').optional(),
  expiresAt: z.iso.datetime({ offset: true }).optional(),
  transactionId: z.uuidv7(),
  state: z.string().min(32).max(256),
  nonce: z.string().min(32).max(256),
  codeChallenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
  issuer: z.url(),
  clientId: z.string().min(1),
  redirectUri: z.url(),
});
const custodySchema = invitationProofInput
  .omit({ token: true })
  .extend({
    transactionId: z.uuidv7(),
    state: z.string(),
    identityCookie: z.string().regex(/^__Host-openpc_invitation_oidc=[A-Za-z0-9._-]+$/u),
    origin: z.url(),
    issuedAt: z.number().int().nonnegative(),
    expiresAt: z.number().int().positive().optional(),
    issuer: z.url().optional(),
  })
  .strict();
const opened = (request: NextRequest, runtime: LocalConfig) =>
  custodySchema.safeParse(
    openBffPayload(request.cookies.get(cookieName)?.value, runtime.cookieKey, 'invitation-custody'),
  );

export async function beginInvitationProof(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const input = invitationProofInput
    .extend({ loginHint: z.string().trim().min(1).max(256).optional() })
    .strict()
    .safeParse(parsePublicCommand(await request.text()));
  if (!input.success) return safeProblem('PC-DATA-6004', request);
  const { invitationId, loginHint, ...body } = input.data;
  const response = await fetch(
    `${runtime.identityUrl}/v1/identity/invitations/${invitationId}/oidc/begin`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  ).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const authorization = authorizationSchema.safeParse(await response.json().catch(() => undefined));
  const identityCookie = /(?:^|[,\s])(__Host-openpc_invitation_oidc=[A-Za-z0-9._-]+)/u.exec(
    response.headers.get('set-cookie') ?? '',
  )?.[1];
  if (
    !authorization.success ||
    !identityCookie ||
    !oidcProviderTransportMatches(runtime.oidcAuthorizationUrl, authorization.data.issuer) ||
    !identityCookie.startsWith(
      `__Host-openpc_invitation_oidc=${authorization.data.transactionId}.`,
    ) ||
    authorization.data.redirectUri !== new URL(callbackPath, request.headers.get('origin')!).href
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const issuedAt = Date.now();
  const nativeExpiresAt = authorization.data.expiresAt
    ? Date.parse(authorization.data.expiresAt)
    : issuedAt + age;
  const expiresAt = Math.min(nativeExpiresAt, issuedAt + age);
  if (expiresAt <= issuedAt) return safeProblem('PC-INTEGRATION-5001', request);
  // Native QA metadata is accepted without extending browser proof custody.
  const target = new URL(runtime.oidcAuthorizationUrl);
  target.search = new URLSearchParams({
    response_type: 'code',
    scope: 'openid',
    client_id: authorization.data.clientId,
    redirect_uri: authorization.data.redirectUri,
    state: authorization.data.state,
    nonce: authorization.data.nonce,
    code_challenge: authorization.data.codeChallenge,
    code_challenge_method: 'S256',
    prompt: 'login',
    ...(loginHint ? { login_hint: loginHint } : {}),
  }).toString();
  const result = NextResponse.json({ authorizationUri: target.href }, { headers: noStore });
  result.cookies.set(
    cookieName,
    sealBffPayload(
      {
        invitationId,
        participantId: body.participantId,
        privacyDomainId: body.privacyDomainId,
        tokenVersion: body.tokenVersion,
        transactionId: authorization.data.transactionId,
        state: authorization.data.state,
        identityCookie,
        origin: request.headers.get('origin'),
        issuedAt,
        issuer: authorization.data.issuer,
        expiresAt,
      },
      runtime.cookieKey,
      'invitation-custody',
    ),
    {
      httpOnly: true,
      secure: request.nextUrl.protocol === 'https:',
      sameSite: 'lax',
      path: callbackPath,
      maxAge: Math.ceil((expiresAt - issuedAt) / 1000),
    },
  );
  return result;
}

/** State chooses between separately sealed login and invitation custody on the configured callback. */
export function isInvitationProofCallback(request: NextRequest, runtime: LocalConfig) {
  const custody = opened(request, runtime);
  return custody.success && custody.data.state === request.nextUrl.searchParams.get('state');
}
export async function completeInvitationProof(request: NextRequest, runtime: LocalConfig) {
  const custody = opened(request, runtime),
    params = request.nextUrl.searchParams;
  if (
    request.nextUrl.pathname !== callbackPath ||
    !custody.success ||
    !validOidcProviderResponse(params, custody.success ? custody.data.issuer : undefined, 8192) ||
    !params.get('code') ||
    params.get('code')!.length > 8192 ||
    params.get('state') !== custody.data.state ||
    custody.data.issuedAt > Date.now() ||
    Date.now() - custody.data.issuedAt >= age ||
    (custody.data.expiresAt !== undefined && custody.data.expiresAt <= Date.now())
  )
    return safeProblem('PC-AUTH-0002', request);
  const binding = custody.data;
  const response = await fetch(
    `${runtime.identityUrl}/v1/identity/invitations/${binding.invitationId}/oidc/callback`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Cookie': binding.identityCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        participantId: binding.participantId,
        privacyDomainId: binding.privacyDomainId,
        transactionId: binding.transactionId,
        state: binding.state,
        authorizationCode: params.get('code'),
      }),
    },
  ).catch(() => undefined);
  if (response?.status === 401 || response?.status === 403) {
    const result = NextResponse.redirect(
      new URL(
        '/govern/memberships?view=invitation-acceptance&invitationError=identity_not_verified',
        binding.origin,
      ),
      303,
    );
    result.headers.set('Cache-Control', 'no-store');
    for (const [name, path] of [
      [cookieName, callbackPath],
      [resultCookie, '/api/v1/ui/invitation-proof'],
    ] as const)
      result.cookies.set(name, '', {
        httpOnly: true,
        secure: request.nextUrl.protocol === 'https:',
        sameSite: 'lax',
        path,
        maxAge: 0,
      });
    return result;
  }
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const accepted = privateAcceptance.safeParse(await response.json().catch(() => undefined));
  if (
    !accepted.success ||
    accepted.data.invitationId !== binding.invitationId ||
    accepted.data.participantId !== binding.participantId ||
    accepted.data.privacyDomainId !== binding.privacyDomainId ||
    accepted.data.tokenVersion !== binding.tokenVersion ||
    response.headers.has('set-cookie')
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const result = NextResponse.redirect(
    new URL('/govern/memberships?view=invitation-acceptance', binding.origin),
    303,
  );
  result.headers.set('Cache-Control', 'no-store');
  result.cookies.set(
    resultCookie,
    sealBffPayload(
      { acceptance: accepted.data, issuedAt: Date.now() },
      runtime.cookieKey,
      'invitation-result',
    ),
    {
      httpOnly: true,
      secure: request.nextUrl.protocol === 'https:',
      sameSite: 'strict',
      path: '/api/v1/ui/invitation-proof',
      maxAge: (accepted.data.bootstrap ? bootstrapAge : age) / 1000,
    },
  );
  return result;
}
export async function readInvitationResult(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const result = invitationBootstrapCustody(request, runtime);
  if (!result) return NextResponse.json({ acceptance: null }, { headers: noStore });
  const { bootstrap, ...acceptance } = result;
  return NextResponse.json(
    { acceptance, ...(bootstrap ? { firstAdministrator: true } : {}) },
    { headers: noStore },
  );
}
