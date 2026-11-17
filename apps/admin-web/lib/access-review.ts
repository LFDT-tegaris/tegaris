import { z } from 'zod';
import {
  grantKinds,
  grantPermission,
  grantReadback,
  grantRevision,
} from '../components/grant-workflow-contract';

export const accessReviewCursor = z.string().regex(/^(?:assignment|delegation):[0-9a-f-]{36}$/u);
export const accessReviewTarget = z.strictObject({ id: z.uuid(), kind: grantKinds });
const scope = grantPermission.extend({
  participantId: z.uuid(),
  resourceIds: z.array(z.string().min(1).max(512)).max(256),
  riskClasses: z.array(z.string().min(1).max(512)).max(256),
});
export const accessReviewPage = z.strictObject({
  authoritative: z.literal(false),
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  subject: z.strictObject({
    id: z.uuid(),
    kind: z.string(),
    state: z.string(),
    authorityEpoch: grantRevision,
  }),
  participantEpoch: grantRevision,
  observedAt: z.string().datetime(),
  items: z
    .array(
      z.strictObject({
        grant: grantReadback,
        assignmentId: z.uuid(),
        envelopeId: z.uuid(),
        envelopeEpoch: grantRevision,
        ancestry: z
          .array(
            z.strictObject({
              id: z.uuid(),
              kind: grantKinds,
              revision: grantRevision,
              state: z.string(),
            }),
          )
          .min(1)
          .max(33),
        constraints: scope,
        current: z.boolean(),
        reasons: z.array(z.string()).max(16),
        remediation: accessReviewTarget.extend({ revision: grantRevision }).nullable(),
      }),
    )
    .max(50),
  nextCursor: accessReviewCursor.nullable(),
  completeness: z.enum(['COMPLETE', 'MORE']),
  authorizedEmpty: z.boolean(),
  decisionBoundary: z.literal('CURRENT_GRANT_INTERSECTION_REQUIRES_LIVE_REQUEST_AUTHORIZATION'),
});
export type AccessReviewPage = z.infer<typeof accessReviewPage>;
