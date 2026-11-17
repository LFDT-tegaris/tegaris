import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createExplorerProfileSchema, revokeExplorerProfileSchema } from './profile-contract.js';
import {
  registerExplorerProfile,
  validateExplorerProfile,
} from '../../privacy-explorer/profile-registration.js';

const fixture = JSON.parse(
  readFileSync(
    new URL(
      '../../../../../tests/fixtures/privacy-explorer/i07-gate2-b2-registered-profile.json',
      import.meta.url,
    ),
    'utf8',
  ),
);
const { registrationId, ...profile } = fixture.profileRegistration;
const action = {
  actionIntentDigest: `sha256:${'ab'.repeat(32)}`,
  reason: 'Register the exact audit export configuration.',
};

describe('governed Explorer profile boundary', () => {
  it('uses the existing exact profile validator and does not create a registered authority token', () => {
    const body = {
      ...action,
      actionIntentId: 'ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1',
      profile,
    };
    expect(createExplorerProfileSchema.parse(body).profile).toEqual(
      validateExplorerProfile(profile),
    );
    expect(() => registerExplorerProfile(profile, { verify: () => undefined })).toThrow(
      'unqualified Explorer profile',
    );
    for (const changed of [
      { ...profile, ready: true },
      { ...profile, allowedFieldIds: [...profile.allowedFieldIds, 'PEF-HIDDEN'] },
      { ...profile, maximumDeadlineAt: '2030-02-30T00:00:00Z' },
      { ...profile, digest: `sha256:${'cd'.repeat(32)}` },
    ])
      expect(createExplorerProfileSchema.safeParse({ ...body, profile: changed }).success).toBe(
        false,
      );
    expect(createExplorerProfileSchema.safeParse({ ...body, registrationId }).success).toBe(false);
  });
  it('binds revocation to an exact revision without accepting a replacement profile or caller state', () => {
    const body = {
      ...action,
      actionIntentId: 'ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1',
      expectedRevision: '1',
    };
    expect(revokeExplorerProfileSchema.parse(body)).toEqual(body);
    for (const amendment of [
      { profile },
      { state: 'REGISTERED' },
      { expectedRevision: '0' },
      { expectedRevision: '01' },
    ])
      expect(revokeExplorerProfileSchema.safeParse({ ...body, ...amendment }).success).toBe(false);
  });
});
