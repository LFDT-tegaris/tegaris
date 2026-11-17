import { z } from 'zod';
import { enrollmentSessionSchema } from './authenticator-enrollment';

const authenticatedSession = enrollmentSessionSchema
  .extend({
    enabled: z.literal(true),
    role: z.enum(['operator', 'viewer']),
    functionalTest: z.literal(true).optional(),
    functionalPlatformConfigured: z.literal(true).optional(),
    contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
    privacyDomainId: z.uuid().optional(),
  })
  .refine((value) => value.contextMode === 'PLATFORM' || value.privacyDomainId !== undefined);

export const localSessionStatusSchema = z.union([
  z.object({ enabled: z.literal(false) }),
  z.object({ enabled: z.literal(true), authenticated: z.literal(false) }),
  authenticatedSession,
]);

export type AuthenticatedLocalSession = z.infer<typeof authenticatedSession>;
