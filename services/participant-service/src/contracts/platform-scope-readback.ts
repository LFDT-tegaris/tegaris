import { z } from 'zod';
import { envelopeScopeSchema } from './envelope.js';
import {
  platformScopeAffectedTarget,
  platformScopeSupersession,
} from './platform-scope-replacement.js';

const revision = z.string().regex(/^[1-9][0-9]{0,19}$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const platformScopeSourceSchema = z.strictObject({
  root: z.strictObject({
    platformContextId: z.uuidv7(),
    ownerParticipantId: z.uuidv7(),
    installationPrivacyDomainId: z.uuidv7(),
    platformAuthorityEpoch: revision,
    environmentId: z.string().min(1),
    installationDigest: digest,
    grantable: envelopeScopeSchema,
    platformAuthorityDigest: digest,
  }),
  revision,
  epoch: revision,
  state: z.enum(['ACTIVE', 'SUSPENDED', 'REVOKED']),
  now: revision,
  pending: z.uuidv7().nullable(),
  pendingIntent: platformScopeSupersession.nullable().optional(),
  pendingAdministrationExpiresAtNs: revision.nullable().optional(),
  affectedTargets: z.array(platformScopeAffectedTarget).max(256),
});

export const platformScopeReadinessSchema = z
  .strictObject({
    replacementId: z.uuidv7(),
    platformContextId: z.uuidv7(),
    rootRevision: revision,
    predecessorEpoch: revision,
    predecessorDigest: digest,
    successorDigest: digest,
    readinessDigest: digest,
    replacementRevision: revision,
    state: z.enum(['WITHDRAWING', 'COMMITTED']),
    unacknowledgedTargets: z.number().int().min(0).max(256),
    unpreparedAdministrators: z.number().int().min(0).max(16),
    sourceExpiresAtNs: revision,
    nowNs: revision,
    targets: z.array(z.object({ targetId: z.uuidv7(), ready: z.boolean() }).passthrough()).max(256),
    administrators: z
      .array(
        z
          .object({
            principalId: z.uuidv7(),
            envelopeId: z.uuidv7(),
            assignmentId: z.uuidv7(),
            ready: z.boolean(),
          })
          .passthrough(),
      )
      .min(2)
      .max(16),
  })
  .superRefine((value, ctx) => {
    if (
      value.targets.filter((target) => !target.ready).length !== value.unacknowledgedTargets ||
      value.administrators.filter((admin) => !admin.ready).length !== value.unpreparedAdministrators
    )
      ctx.addIssue({ code: 'custom', message: 'Inconsistent authoritative readiness counts' });
  });

export type PlatformScopeSourceReadback = z.infer<typeof platformScopeSourceSchema>;
