import {
  localRootExpiryRecoverySourceView,
  localRootExpiryRecoveryDraftView,
  localRootExpiryRecoveryReceiptView,
} from '../../../../../../services/identity-service/src/contracts/local-root-expiry-recovery';
import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  discoveryCertificateRecoveryCommand,
  discoveryCertificateRecoverySourceView,
  discoveryCertificateRecoveryDraftView,
  discoveryCertificateRecoveryReceiptView,
} from '../../../../../../services/identity-service/src/contracts/discovery-certificate-recovery';
import {
  platformRecoveryCommand,
  platformRecoverySourceView,
  platformRecoveryDraftView,
  platformRecoveryChallengeView,
  platformRecoveryReceiptView,
} from '../../../../../../services/identity-service/src/contracts/platform-recovery';
import {
  identityEnvelopeRecoverySourceView,
  identityEnvelopeRecoveryDraftView,
  identityEnvelopeRecoveryReceiptView,
  identityEnvelopeRecoveryRotationCreationView,
  identityEnvelopeRecoveryRotationQueueView,
} from '../../../../../../services/identity-service/src/contracts/identity-envelope-recovery';
import {
  authenticated,
  hasJsonContentType,
  identityCsrf,
  identityOwnerHeaders,
  localRuntimeConfig,
  readPublicCommand,
  localOwnerFetch,
  safeProblem,
  sameOrigin,
} from './local-runtime';
import { ownerJson, isResponse } from './local-governance-api';
const input = z.union([
  z.strictObject({
    enrollmentId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    command: platformRecoveryCommand,
  }),
  z.strictObject({
    purpose: z.literal('DISCOVERY_CERTIFICATE_REPLACEMENT'),
    enrollmentId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    command: discoveryCertificateRecoveryCommand,
  }),
]);
export async function mutatePlatformRecoveryWorkbench(request: NextRequest) {
  if (!sameOrigin(request)) return safeProblem('PC-AUTH-0001', request);
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PLATFORM') return safeProblem('PC-AUTH-0005', request);
  const parsed = input.safeParse(await readPublicCommand(request, 131072));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const body = parsed.data;
  const discovery = 'purpose' in body;
  const csrf = await identityCsrf(runtime, session, 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1');
  if (!csrf) return safeProblem('PC-AUTH-0001', request);
  const response = await localOwnerFetch(
    `${runtime.identityUrl}/v1/identity/${discovery ? 'discovery-certificate-recovery' : 'platform-recovery'}/enrollments/${body.enrollmentId}/commands`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...identityOwnerHeaders(runtime, session, request.headers.get('origin')!),
        'X-CSRF-Token': csrf,
      },
      body: JSON.stringify({ privacyDomainId: body.privacyDomainId, command: body.command }),
    },
  ).catch(() => undefined);
  const schema = discovery
    ? body.command.kind === 'SOURCE'
      ? discoveryCertificateRecoverySourceView
      : body.command.kind === 'CREATE'
        ? discoveryCertificateRecoveryDraftView
        : body.command.kind === 'CHALLENGE'
          ? platformRecoveryChallengeView
          : discoveryCertificateRecoveryReceiptView
    : body.command.kind === 'SOURCE'
      ? z.union([
          platformRecoverySourceView,
          identityEnvelopeRecoverySourceView,
          localRootExpiryRecoverySourceView,
        ])
      : body.command.kind === 'CREATE'
        ? z.union([
            platformRecoveryDraftView,
            identityEnvelopeRecoveryDraftView,
            localRootExpiryRecoveryDraftView,
          ])
        : body.command.kind === 'CHALLENGE'
          ? platformRecoveryChallengeView
          : body.command.kind === 'ROTATION_CREATE'
            ? identityEnvelopeRecoveryRotationCreationView
            : body.command.kind === 'ROTATION_ADVANCE'
              ? identityEnvelopeRecoveryRotationQueueView
              : z.union([
                  platformRecoveryReceiptView,
                  identityEnvelopeRecoveryReceiptView,
                  localRootExpiryRecoveryReceiptView,
                ]);
  const view = await ownerJson(response, schema as z.ZodType<unknown>, request);
  if (isResponse(view)) return view;
  return NextResponse.json(
    {
      actor: {
        sessionId: session.sessionId,
        principalId: session.principalId,
        participantId: session.participantId,
        contextEpoch: session.contextEpoch,
      },
      view,
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
