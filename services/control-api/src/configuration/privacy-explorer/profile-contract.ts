import { z } from 'zod';
import { validateExplorerProfile } from '../../privacy-explorer/profile-registration.js';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';
import type { PrivacyExplorerExportProfileV1 } from '../../contracts/privacy-explorer-adapter.js';

export const explorerProfileDefinitionSchema = z
  .unknown()
  .transform((value, context): PrivacyExplorerExportProfileV1 => {
    try {
      return validateExplorerProfile(value);
    } catch {
      context.addIssue({ code: 'custom', message: 'Invalid Explorer export profile' });
      return z.NEVER;
    }
  });
const action = z.object({ actionIntentDigest: digestSchema, reason: z.string().min(1).max(1024) });
export const createExplorerProfileSchema = action
  .extend({
    actionIntentId: z.literal('ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1'),
    profile: explorerProfileDefinitionSchema,
  })
  .strict();
export const revokeExplorerProfileSchema = action
  .extend({
    actionIntentId: z.literal('ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1'),
    expectedRevision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  })
  .strict();
export const explorerProfileResponseSchema = z.strictObject({
  registrationId: resourceUrnSchema,
  profile: explorerProfileDefinitionSchema,
  profileDigest: digestSchema,
  state: z.enum(['REGISTERED', 'REVOKED']),
  revision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  publicationOperationId: z.uuid(),
  publicationAuthorityDigest: digestSchema,
  revocationOperationId: z.uuid().nullable(),
  runtimePermission: z.literal('NONE_WITHOUT_ACTIVE_POLICY'),
  createdAt: z.iso.datetime(),
});
