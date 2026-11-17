import { z } from 'zod';
import type { IdentitySession } from '../app/api/v1/ui/local-runtime';

const epoch = z.string().regex(/^[1-9][0-9]*$/u);
const sessionSchema = z
  .object({
    role: z.enum(['operator', 'viewer']),
    sessionId: z.uuid(),
    principalId: z.uuid(),
    participantId: z.uuid(),
    contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
    privacyDomainId: z.uuid().optional(),
    contextEpoch: epoch,
    platformBootstrapEligible: z.boolean().optional(),
    availableContexts: z
      .array(z.strictObject({ participantId: z.uuid(), privacyDomainId: z.uuid() }))
      .optional(),
    sessionEpoch: epoch.optional(),
    participantEpoch: epoch.optional(),
    principalEpoch: epoch.optional(),
    assignmentId: z.uuid().optional(),
    assignmentRowVersion: epoch.optional(),
    authorityEnvelopeId: z.uuid().optional(),
    authorityEpoch: epoch.optional(),
    delegationEpoch: z
      .string()
      .regex(/^(?:0|[1-9][0-9]*)$/u)
      .optional(),
    stepUpVerifiedAt: z.string().datetime().nullable(),
  })
  .refine((session) =>
    session.contextMode === 'PLATFORM'
      ? session.privacyDomainId === undefined
      : session.privacyDomainId !== undefined,
  ) satisfies z.ZodType<Omit<IdentitySession, 'sessionToken'>>;

type SessionRead =
  | { readonly state: 'AUTHENTICATED'; readonly session: Omit<IdentitySession, 'sessionToken'> }
  | { readonly state: 'SIGNED_OUT' }
  | { readonly state: 'UNAVAILABLE' };

/** Only an explicit owner denial confirms sign-out. Failed reads are not
 * permission to reuse an earlier session or discard an uncertain operation. */
export async function readIdentitySessionResponse(
  pending: Promise<Response>,
): Promise<SessionRead> {
  try {
    const response = await pending;
    if (
      response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !==
      'application/json'
    )
      return { state: 'UNAVAILABLE' };
    const body: unknown = await response.json();
    if (response.status === 401) {
      const denied = z.strictObject({ code: z.literal('PC-AUTH-0005') }).safeParse(body);
      return { state: denied.success ? 'SIGNED_OUT' : 'UNAVAILABLE' };
    }
    if (response.status !== 200) return { state: 'UNAVAILABLE' };
    const parsed = sessionSchema.safeParse(body);
    return parsed.success
      ? { state: 'AUTHENTICATED', session: parsed.data }
      : { state: 'UNAVAILABLE' };
  } catch {
    return { state: 'UNAVAILABLE' };
  }
}

export class IdentitySessionUnavailable extends Error {
  constructor() {
    super('Session verification is temporarily unavailable');
  }
}
