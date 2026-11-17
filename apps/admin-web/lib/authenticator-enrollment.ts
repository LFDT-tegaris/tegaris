import { z } from 'zod';

const epoch = z.string().regex(/^[1-9][0-9]*$/u);
export const enrollmentReadbackSchema = z.strictObject({
  enrollmentId: z.uuid(),
  participantId: z.uuid(),
  principalId: z.uuid(),
  principalEpoch: epoch,
  state: z.enum(['PENDING', 'EXPIRED', 'COMPLETED']),
  expiresAt: z.string().datetime(),
  completedAt: z.string().datetime().nullable(),
  credential: z
    .strictObject({ credentialId: z.uuid(), credentialEpoch: epoch, active: z.boolean() })
    .nullable(),
});
export type EnrollmentReadback = z.infer<typeof enrollmentReadbackSchema>;

export const enrollmentSessionSchema = z.object({
  authenticated: z.literal(true),
  sessionId: z.uuid(),
  principalId: z.uuid(),
  participantId: z.uuid(),
  contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
  privacyDomainId: z.uuid().optional(),
  availableContexts: z.array(
    z.strictObject({ participantId: z.uuid(), privacyDomainId: z.uuid() }),
  ),
});
export type EnrollmentSession = z.infer<typeof enrollmentSessionSchema>;
