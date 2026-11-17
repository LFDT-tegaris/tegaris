import { createHash } from 'node:crypto';

import { NextResponse, NextRequest } from 'next/server';
import { z } from 'zod';
import { withFunctionalAssertion } from './functional-test-profile';

import { localFactAction } from '@openpc/ui-shell';
import {
  approvalCreateAction,
  approvalUpdateAction,
  principalCreateAction,
} from './local-governance-api';
import { firstAdministratorMetadata } from '../../../../lib/first-administrator-contract';
import { transactionKinds } from '../../../../lib/transaction-workflow';
import { transactionOperation } from './transaction-workbench-contract';

import {
  authenticated,
  hasJsonContentType,
  identityCsrf,
  identityOwnerHeaders,
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

const custodyCookie = 'openpc_webauthn_custody';
const maximumChallengeAgeMs = 5 * 60 * 1000;
const challengePath = '/api/v1/ui/webauthn/assertion/challenge';
const verifyPath = '/api/v1/ui/webauthn/assertion/verify';
const approvalActionIntentId = 'ACT-POLICY_APPROVE_REQUEST-V1';
const approvalActionIntentDigest =
  'sha256:460403d23ce1c8fb48362b045fb558200fb3ea7ab73469546730b067c1d63cd8';
const publishActionIntentId = 'ACT-POLICY_ACTIVATE_PUBLISH-V1';
const publishActionIntentDigest =
  'sha256:69027f899349c765077f9a9dfdc7868bb92c653a071347251d22c8bcf87c4edb';
const activateActionIntentId = 'ACT-POLICY_ACTIVATE_RELEASE-V1';
const activateActionIntentDigest =
  'sha256:6dd0e7edc1933d43beb79a0156559f9fc56f729fbc761cfb7770dd50bce8734c';
const rollbackActionIntentId = 'ACT-POLICY_ROLLBACK_RELEASE-V1';
const rollbackActionIntentDigest =
  'sha256:d5bc5ec3e43562a072ee107859df6803c0394add98d9e1837bf5b8074689914d';
const participantActionIntentId = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const participantActionIntentDigest =
  'sha256:bec5bb71e10db36e744f98a55dd6b54a0c42f9f55b73ac322a1de6e8592fd529';
const participantReadActionIntentId = 'ACT-PARTICIPANTS_READ_RESOURCE-V1';
const participantReadActionIntentDigest =
  'sha256:73a4a8e0cc469d63163715b94ce3882d4a66e86e3d7799cb7089dd3c5aff8ad0';
const envelopeActivationActionIntentId = 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1';
const envelopeActivationActionIntentDigest =
  'sha256:a3de751c7a68380154458c737a54b0d7de5328e33f83b8e37bd5ef610b2304c4';
const contextActionIntentId = 'ACT-IDENTITY_CREATE_SESSION-V1';
const contextActionIntentDigest =
  'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2';
const bootstrapActions = new Set([
  'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
]);
const checkerActionIntents = new Map<string, string>([
  [approvalActionIntentId, approvalActionIntentDigest],
  [publishActionIntentId, publishActionIntentDigest],
  [activateActionIntentId, activateActionIntentDigest],
  [rollbackActionIntentId, rollbackActionIntentDigest],
  [
    'ACT-FLEET_RECOVER_OCCURRENCE-V1',
    'sha256:4dac3f1679a92c185899c5142e16f23d465b043112781f1686853a8e7679ab1d',
  ],
  [envelopeActivationActionIntentId, envelopeActivationActionIntentDigest],
]);
const transactionActionIntents = new Map(
  transactionKinds.map((kind) => {
    const operation = transactionOperation(kind);
    return [operation.actionIntentId, operation.actionIntentDigest];
  }),
);
// Endpoint action-registry digests. Identity still authenticates the
// actor and consumes the one-use assertion for this candidate at mutation time.
const notificationEndpointActionIntents = new Map([
  [
    'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
    'sha256:5c86363197220c6ef9e4dfa653b551c758e2fd117276fa0fe8f2bdaa49a7ffc0',
  ],
  [
    'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
    'sha256:8d3db9f82f631334222a946973f6ea8de29484f231b566a6bef0d16792b2a5ec',
  ],
]);
const digestSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const base64UrlSchema = z.string().regex(/^[A-Za-z0-9_-]+$/u);
const actionSchema = z
  .object({
    actionIntentId: z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u),
    actionIntentDigest: digestSchema,
    resourceId: z.uuid().optional(),
    resourceDigest: digestSchema.optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const fact =
      value.actionIntentId === localFactAction.actionIntentId &&
      value.actionIntentDigest === localFactAction.actionIntentDigest &&
      value.resourceId === undefined &&
      value.resourceDigest === undefined;
    const governed =
      (bootstrapActions.has(value.actionIntentId) ||
        checkerActionIntents.get(value.actionIntentId) === value.actionIntentDigest ||
        transactionActionIntents.get(value.actionIntentId) === value.actionIntentDigest ||
        notificationEndpointActionIntents.get(value.actionIntentId) === value.actionIntentDigest ||
        (value.actionIntentId === approvalCreateAction.id &&
          value.actionIntentDigest === approvalCreateAction.digest) ||
        (value.actionIntentId === approvalUpdateAction.id &&
          value.actionIntentDigest === approvalUpdateAction.digest) ||
        (value.actionIntentId === participantActionIntentId &&
          value.actionIntentDigest === participantActionIntentDigest) ||
        (value.actionIntentId === participantReadActionIntentId &&
          value.actionIntentDigest === participantReadActionIntentDigest) ||
        (value.actionIntentId === principalCreateAction.id &&
          value.actionIntentDigest === principalCreateAction.digest) ||
        (value.actionIntentId === contextActionIntentId &&
          value.actionIntentDigest === contextActionIntentDigest)) &&
      value.resourceId !== undefined &&
      value.resourceDigest !== undefined;
    if (!fact && !governed) context.addIssue({ code: 'custom', message: 'action is not admitted' });
  });
const verificationSchema = actionSchema
  .extend({
    challenge: base64UrlSchema.min(32).max(256),
    assertion: z
      .object({
        credentialId: base64UrlSchema.max(256),
        authenticatorData: base64UrlSchema.max(4096),
        clientDataJson: base64UrlSchema.max(4096),
        signature: base64UrlSchema.max(4096),
      })
      .strict(),
  })
  .strict();
const identityChallengeSchema = z
  .object({
    challenge: base64UrlSchema.min(32).max(256),
    durationProfile: z.literal('LOCAL_QA_10X').optional(),
    expiresAt: z.iso.datetime({ offset: true }).optional(),
    credentialIds: z.array(base64UrlSchema.min(1).max(1024)).min(1).max(20),
  })
  .strict();
const custodySchema = z
  .object({
    sessionId: z.uuid(),
    principalId: z.uuid(),
    participantId: z.uuid(),
    privacyDomainId: z.uuid().optional(),
    contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
    actionIntentId: z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u),
    actionIntentDigest: digestSchema,
    ownerActionIntentId: z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u),
    ownerMutationActionIntentDigest: digestSchema,
    resourceId: z.uuid(),
    resourceDigest: digestSchema,
    challenge: base64UrlSchema.min(32).max(256),
    origin: z.url(),
    host: z.string().min(1).max(255),
    rpIdHash: digestSchema,
    revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
    idempotencyKey: z.string().min(16).max(128),
    credentialBindings: z
      .array(
        z
          .object({
            browserCredentialId: base64UrlSchema.min(1).max(2048),
            ownerCredentialId: base64UrlSchema.min(1).max(1024),
          })
          .strict(),
      )
      .min(1)
      .max(20),
    issuedAt: z.number().int().nonnegative(),
    expiresAt: z.number().int().positive().optional(),
    durationProfile: z.literal('LOCAL_QA_10X').optional(),
  })
  .strict();
const mutationContextSchema = z
  .object({
    revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
    actionIntentDigest: digestSchema,
  })
  .strict();
const verifiedSchema = z.object({ status: z.literal('verified') }).strict();

async function webAuthnOwnerFailure(stage: string, response?: Response): Promise<void> {
  const upstream = response
    ? z
        .object({ error: z.object({ code: z.string().max(80) }).passthrough() })
        .passthrough()
        .safeParse(
          await response
            .clone()
            .json()
            .catch(() => undefined),
        )
    : undefined;
  process.stderr.write(
    `OPENPC_LOCAL_WEBAUTHN_FAILURE|stage=${stage}|upstream_status=${response?.status ?? 0}|upstream_code=${upstream?.success ? upstream.data.error.code : 'unclassified'}\n`,
  );
}

function roleAdmitted(actionIntentId: string, role: IdentitySession['role']): boolean {
  // Governance authority belongs to Identity's actual principal and candidate checks.
  // The local fact demonstration retains its existing presentation profile.
  return actionIntentId !== localFactAction.actionIntentId || role === 'operator';
}

async function sessionMutationContext(runtime: LocalConfig, session: IdentitySession) {
  const response = await localOwnerFetch(
    `${runtime.identityUrl}/internal/v1/local/session/mutation-version`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Authorization': `Bearer ${runtime.identityToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ sessionToken: session.sessionToken }),
    },
  ).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type'))) return undefined;
  const parsed = mutationContextSchema.safeParse(await response.json());
  return parsed.success ? parsed.data : undefined;
}

function rpIdHash(request: NextRequest): string {
  return `sha256:${createHash('sha256')
    .update(new URL(request.headers.get('origin')!).hostname)
    .digest('hex')}`;
}

function credentialBindings(ownerCredentialIds: readonly string[]) {
  return ownerCredentialIds.map((ownerCredentialId) => ({
    ownerCredentialId,
    browserCredentialId: z.uuid().safeParse(ownerCredentialId).success
      ? Buffer.from(ownerCredentialId, 'utf8').toString('base64url')
      : ownerCredentialId,
  }));
}

function requestAdmitted(request: NextRequest, path: string): boolean {
  return (
    request.method === 'POST' &&
    request.nextUrl.pathname === path &&
    sameOrigin(request) &&
    hasJsonContentType(request.headers.get('content-type'))
  );
}

export async function beginLocalWebAuthnAssertion(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  if (!requestAdmitted(request, challengePath)) return safeProblem('PC-AUTH-0002', request);
  const action = actionSchema.safeParse(parsePublicCommand(await request.text()));
  if (!action.success) return safeProblem('PC-DATA-6004', request);
  if (!roleAdmitted(action.data.actionIntentId, session.role)) {
    return safeProblem('PC-AUTH-0005', request);
  }
  if (bootstrapActions.has(action.data.actionIntentId)) {
    if (
      session.contextMode !== 'PLATFORM' ||
      session.platformBootstrapEligible !== true ||
      (action.data.actionIntentId === 'ACT-IDENTITY_UPDATE_STEP_UP-V1' &&
        action.data.resourceId !== session.sessionId)
    )
      return safeProblem('PC-AUTH-0005', request);
    const response = await localOwnerFetch(
      `${runtime.publicApiUrl}/v1/participants/bootstrap-metadata`,
      {
        cache: 'no-store',
        headers: { Authorization: `Bearer ${session.sessionToken}` },
      },
    ).catch(() => undefined);
    const metadata = firstAdministratorMetadata.safeParse(
      response?.ok && hasJsonContentType(response.headers.get('content-type'))
        ? await response.json().catch(() => undefined)
        : undefined,
    );
    if (
      !metadata.success ||
      metadata.data.participantId !== session.participantId ||
      action.data.actionIntentDigest !==
        (action.data.actionIntentId === 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1'
          ? metadata.data.actionIntentDigest
          : metadata.data.stepUpActionIntentDigest)
    )
      return safeProblem('PC-AUTH-0005', request);
  }
  const ownerBinding =
    action.data.actionIntentId === localFactAction.actionIntentId
      ? {
          ownerActionIntentId: localFactAction.downstreamActionIntentId,
          resourceId: localFactAction.resourceRef.split(':').at(-1)!,
          resourceDigest: localFactAction.inputDigest,
        }
      : {
          ownerActionIntentId: action.data.actionIntentId,
          resourceId: action.data.resourceId!,
          resourceDigest: action.data.resourceDigest!,
        };
  const csrfToken = await identityCsrf(runtime, session, ownerBinding.ownerActionIntentId);
  if (!csrfToken) return safeProblem('PC-AUTH-0005', request);
  const binding = rpIdHash(request);
  const identityResponse = await localOwnerFetch(
    `${runtime.identityUrl}/v1/identity/webauthn/assertion/challenge`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...identityOwnerHeaders(runtime, session),
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        actionIntentId: ownerBinding.ownerActionIntentId,
        resourceId: ownerBinding.resourceId,
        resourceDigest: ownerBinding.resourceDigest,
        rpIdHash: binding,
      }),
    },
  ).catch(() => undefined);
  if (!identityResponse?.ok || !hasJsonContentType(identityResponse.headers.get('content-type'))) {
    await webAuthnOwnerFailure('assertion-challenge-owner', identityResponse);
    return safeProblem(identityResponse ? 'PC-AUTH-0006' : 'PC-INTEGRATION-5001', request);
  }
  const challengeBody = await identityResponse.json();
  const challenge = identityChallengeSchema.safeParse(challengeBody);
  const mutationContext = await sessionMutationContext(runtime, session);
  if (!challenge.success || mutationContext === undefined) {
    if (!challenge.success) {
      const shape =
        typeof challengeBody === 'object' && challengeBody !== null && !Array.isArray(challengeBody)
          ? {
              keys: Object.keys(challengeBody).sort(),
              challengeType: typeof (challengeBody as Record<string, unknown>).challenge,
              challengeLength:
                typeof (challengeBody as Record<string, unknown>).challenge === 'string'
                  ? ((challengeBody as Record<string, unknown>).challenge as string).length
                  : -1,
              credentialCount: Array.isArray(
                (challengeBody as Record<string, unknown>).credentialIds,
              )
                ? ((challengeBody as Record<string, unknown>).credentialIds as unknown[]).length
                : -1,
              issues: challenge.error.issues.map((issue) => ({
                code: issue.code,
                path: issue.path.join('.'),
              })),
            }
          : { bodyType: typeof challengeBody };
      process.stderr.write(
        `OPENPC_LOCAL_WEBAUTHN_CHALLENGE_SHAPE|detail=${JSON.stringify(shape)}\n`,
      );
    }
    await webAuthnOwnerFailure(
      challenge.success ? 'assertion-challenge-revision' : 'assertion-challenge-shape',
    );
    return safeProblem('PC-INTEGRATION-5001', request);
  }
  const bindings = credentialBindings(challenge.data.credentialIds);
  const idempotencyKey = `webauthn-${createHash('sha256')
    .update(session.sessionToken)
    .update('\0')
    .update(challenge.data.challenge)
    .digest('base64url')}`;
  const challengeAgeMs =
    challenge.data.durationProfile === 'LOCAL_QA_10X' ? 3_000_000 : maximumChallengeAgeMs;
  const issuedAt = Date.now();
  const expiresAt =
    challenge.data.expiresAt === undefined
      ? issuedAt + maximumChallengeAgeMs
      : Date.parse(challenge.data.expiresAt);
  if (
    (challenge.data.durationProfile !== undefined && challenge.data.expiresAt === undefined) ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= issuedAt ||
    expiresAt > issuedAt + challengeAgeMs
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  const response = NextResponse.json(
    {
      publicKey: {
        challenge: challenge.data.challenge,
        rpId: new URL(request.headers.get('origin')!).hostname,
        allowCredentials: bindings.map((credential) => ({
          id: credential.browserCredentialId,
          type: 'public-key' as const,
        })),
        timeout: Math.min(challengeAgeMs, expiresAt - issuedAt),
        userVerification: 'required' as const,
      },
      expiresAt: rfc3339Micros(expiresAt),
      ...(runtime.functionalTest ? { functionalTest: true } : {}),
      ...(challenge.data.durationProfile
        ? { durationProfile: challenge.data.durationProfile }
        : {}),
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
  response.cookies.set(
    custodyCookie,
    sealBffPayload(
      {
        sessionId: session.sessionId,
        principalId: session.principalId,
        participantId: session.participantId,
        ...(session.privacyDomainId ? { privacyDomainId: session.privacyDomainId } : {}),
        contextEpoch: session.contextEpoch,
        ...action.data,
        ...ownerBinding,
        challenge: challenge.data.challenge,
        origin: request.headers.get('origin'),
        host: request.headers.get('host'),
        rpIdHash: binding,
        revision: mutationContext.revision,
        ownerMutationActionIntentDigest: mutationContext.actionIntentDigest,
        idempotencyKey,
        credentialBindings: bindings,
        issuedAt,
        ...(challenge.data.expiresAt !== undefined ? { expiresAt } : {}),
        ...(challenge.data.durationProfile
          ? { durationProfile: challenge.data.durationProfile }
          : {}),
      },
      runtime.cookieKey,
      'webauthn-custody',
    ),
    {
      httpOnly: true,
      secure: request.nextUrl.protocol === 'https:',
      sameSite: 'strict',
      path: '/api/v1/ui/webauthn',
      maxAge: Math.floor((expiresAt - issuedAt) / 1000),
    },
  );
  return response;
}

export async function completeLocalWebAuthnAssertion(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  if (!requestAdmitted(request, verifyPath)) return safeProblem('PC-AUTH-0002', request);
  const input = verificationSchema.safeParse(parsePublicCommand(await request.text()));
  const custody = custodySchema.safeParse(
    openBffPayload(
      request.cookies.get(custodyCookie)?.value,
      runtime.cookieKey,
      'webauthn-custody',
    ),
  );
  if (
    !input.success ||
    !custody.success ||
    session.sessionId !== custody.data.sessionId ||
    session.principalId !== custody.data.principalId ||
    session.participantId !== custody.data.participantId ||
    session.privacyDomainId !== custody.data.privacyDomainId ||
    session.contextEpoch !== custody.data.contextEpoch ||
    input.data.actionIntentId !== custody.data.actionIntentId ||
    input.data.actionIntentDigest !== custody.data.actionIntentDigest ||
    input.data.challenge !== custody.data.challenge ||
    (input.data.actionIntentId !== localFactAction.actionIntentId &&
      (input.data.resourceId !== custody.data.resourceId ||
        input.data.resourceDigest !== custody.data.resourceDigest)) ||
    request.headers.get('origin') !== custody.data.origin ||
    request.headers.get('host') !== custody.data.host ||
    custody.data.issuedAt > Date.now() ||
    Date.now() >= (custody.data.expiresAt ?? custody.data.issuedAt + maximumChallengeAgeMs) ||
    (custody.data.durationProfile !== undefined && custody.data.expiresAt === undefined) ||
    (custody.data.expiresAt ?? 0) >
      custody.data.issuedAt + (custody.data.durationProfile ? 3_000_000 : maximumChallengeAgeMs)
  ) {
    return safeProblem('PC-AUTH-0006', request);
  }
  if (!roleAdmitted(custody.data.actionIntentId, session.role)) {
    return safeProblem('PC-AUTH-0005', request);
  }
  const credentialId = custody.data.credentialBindings.find(
    (binding) => binding.browserCredentialId === input.data.assertion.credentialId,
  )?.ownerCredentialId;
  const csrfToken = await identityCsrf(runtime, session, custody.data.ownerActionIntentId);
  if (!credentialId || !csrfToken) return safeProblem('PC-AUTH-0006', request);
  const identityResponse = await localOwnerFetch(
    `${runtime.identityUrl}/v1/identity/webauthn/assertion/verify`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...identityOwnerHeaders(runtime, session),
        'Authorization': `Bearer ${runtime.identityToken}`,
        'Idempotency-Key': custody.data.idempotencyKey,
        'X-OpenPC-Browser-Origin': custody.data.origin,
        'X-OpenPC-Aggregate-Version': custody.data.revision,
        'OpenPC-Action-Intent-Digest': custody.data.ownerMutationActionIntentDigest,
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        actionIntentId: custody.data.ownerActionIntentId,
        resourceId: custody.data.resourceId,
        resourceDigest: custody.data.resourceDigest,
        rpIdHash: custody.data.rpIdHash,
        challenge: custody.data.challenge,
        assertion: JSON.stringify({ ...input.data.assertion, credentialId }),
      }),
    },
  ).catch(() => undefined);
  if (!identityResponse?.ok || !hasJsonContentType(identityResponse.headers.get('content-type'))) {
    await webAuthnOwnerFailure('assertion-verify-owner', identityResponse);
    return safeProblem(identityResponse ? 'PC-AUTH-0006' : 'PC-INTEGRATION-5001', request);
  }
  const verified = verifiedSchema.safeParse(await identityResponse.json());
  const refreshed = verified.success ? await authenticated(request, runtime) : undefined;
  const verifiedAt = refreshed?.stepUpVerifiedAt
    ? Date.parse(refreshed.stepUpVerifiedAt)
    : Number.NaN;
  if (
    !verified.success ||
    !refreshed ||
    !Number.isFinite(verifiedAt) ||
    verifiedAt > Date.now() ||
    Date.now() - verifiedAt > maximumChallengeAgeMs
  ) {
    await webAuthnOwnerFailure('assertion-verify-readback');
    return safeProblem('PC-AUTH-0006', request);
  }
  const response = NextResponse.json(
    { status: 'verified', stepUpVerifiedAt: rfc3339Micros(verifiedAt) },
    { headers: { 'Cache-Control': 'no-store' } },
  );
  response.cookies.set(custodyCookie, '', {
    httpOnly: true,
    secure: request.nextUrl.protocol === 'https:',
    sameSite: 'strict',
    path: '/api/v1/ui/webauthn',
    maxAge: 0,
  });
  return response;
}

export async function completeFunctionalTestAssertion(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime?.functionalTest) return safeProblem('PC-AUTH-0005', request);
  if (!requestAdmitted(request, '/api/v1/ui/webauthn/assertion/functional'))
    return safeProblem('PC-AUTH-0002', request);
  const session = await authenticated(request, runtime);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  const body = parsePublicCommand(await request.text());
  if (!body || typeof body !== 'object' || Array.isArray(body))
    return safeProblem('PC-DATA-6004', request);
  const { challenge, ...action } = body as Record<string, unknown>;
  const parsedAction = actionSchema.safeParse(action);
  const parsedChallenge = base64UrlSchema.min(32).max(256).safeParse(challenge);
  const custody = custodySchema.safeParse(
    openBffPayload(
      request.cookies.get(custodyCookie)?.value,
      runtime.cookieKey,
      'webauthn-custody',
    ),
  );
  const actor = runtime.functionalTest.actors[session.role];
  if (
    !parsedAction.success ||
    !parsedChallenge.success ||
    !custody.success ||
    custody.data.sessionId !== session.sessionId ||
    custody.data.principalId !== actor.principalId ||
    custody.data.challenge !== parsedChallenge.data ||
    !custody.data.credentialBindings.some(
      (entry) => entry.ownerCredentialId === actor.assertionCredentialId,
    )
  )
    return safeProblem('PC-AUTH-0006', request);
  try {
    return await withFunctionalAssertion(
      actor,
      { challenge: parsedChallenge.data, origin: request.headers.get('origin')! },
      (assertion) =>
        completeLocalWebAuthnAssertion(
          new NextRequest(new URL(verifyPath, request.url), {
            method: 'POST',
            headers: request.headers,
            body: JSON.stringify({
              ...parsedAction.data,
              challenge: parsedChallenge.data,
              assertion,
            }),
          }),
        ),
    );
  } catch {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
}
