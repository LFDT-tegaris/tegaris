import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  firstAdministratorState,
  firstAdministratorAssertionOptions,
} from '../../../../../../lib/first-administrator-contract';
import { registrationOptionsSchema } from '../../local-bootstrap-runtime';
import { invitationBootstrapCustody } from '../../local-invitation-proof';
import {
  hasJsonContentType,
  localRuntimeConfig,
  parsePublicCommand,
  safeProblem,
  sameOrigin,
} from '../../local-runtime';
export const dynamic = 'force-dynamic';
const command = z.discriminatedUnion('command', [
  z.strictObject({ command: z.literal('READ') }),
  z.strictObject({ command: z.literal('ENROLL_OPTIONS') }),
  z.strictObject({
    command: z.literal('ENROLL_COMPLETE'),
    enrollmentId: z.uuidv7(),
    response: z.unknown(),
  }),
  z.strictObject({ command: z.literal('ACCEPT_OPTIONS') }),
  z.strictObject({
    command: z.literal('ACCEPT'),
    intentDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    challenge: z.string().min(32).max(256),
    assertion: z.string().min(1).max(32768),
  }),
]);
export async function POST(request: NextRequest) {
  if (!sameOrigin(request) || !hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const custody = invitationBootstrapCustody(request, runtime),
    input = command.safeParse(parsePublicCommand(await request.text()));
  if (!custody?.bootstrap || !input.success) return safeProblem('PC-AUTH-0002', request);
  const response = await fetch(
    `${runtime.identityUrl}/v1/identity/invitations/${custody.invitationId}/first-administrator`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${runtime.identityToken}`,
        'Cookie': `__Host-openpc_first_admin_custody=${custody.bootstrap.sessionToken}`,
        'Origin': new URL(runtime.identityUrl).origin,
        'X-OpenPC-Browser-Origin': request.headers.get('origin')!,
      },
      body: JSON.stringify({
        participantId: custody.participantId,
        privacyDomainId: custody.privacyDomainId,
        request: input.data,
      }),
    },
  ).catch(() => undefined);
  if (!response?.ok || !hasJsonContentType(response.headers.get('content-type')))
    return safeProblem('PC-AUTH-0002', request);
  const value = await response.json().catch(() => undefined);
  const schema =
    input.data.command === 'ENROLL_OPTIONS'
      ? registrationOptionsSchema.omit({ expiresAt: true })
      : input.data.command === 'ENROLL_COMPLETE'
        ? z.strictObject({
            credentialId: z.uuid(),
            state: z.literal('ENROLLED'),
            authorityGranted: z.literal(false),
          })
        : input.data.command === 'ACCEPT_OPTIONS'
          ? firstAdministratorAssertionOptions
          : firstAdministratorState;
  const parsed = schema.safeParse(value);
  if (
    !parsed.success ||
    ('participantId' in parsed.data &&
      (parsed.data.participantId !== custody.participantId ||
        parsed.data.invitationId !== custody.invitationId))
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(parsed.data, { headers: { 'Cache-Control': 'no-store' } });
}
