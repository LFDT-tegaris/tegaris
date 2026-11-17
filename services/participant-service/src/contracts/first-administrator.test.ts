import { describe, expect, it } from 'vitest';
import {
  firstAdminInviteTtl,
  firstAdministratorProposal,
  participantBootstrapConfiguration,
} from './first-administrator.js';

describe('governed first-administrator configuration', () => {
  it('uses the accepted 24-hour default and accepts both duration boundaries', () => {
    expect(participantBootstrapConfiguration.parse({})).toEqual({
      'participant.first_admin_invite_ttl': 86400000,
    });
    expect(firstAdminInviteTtl.parse(900000)).toBe(900000);
    expect(firstAdminInviteTtl.parse(604800000)).toBe(604800000);
  });
  it.each([899999, 604800001, -1, NaN, Infinity, 900000.5, '24h', null])(
    'rejects an invalid effective duration: %s',
    (value) => {
      expect(firstAdminInviteTtl.safeParse(value).success).toBe(false);
    },
  );
  it('rejects setting misspellings instead of silently using the default', () => {
    expect(
      participantBootstrapConfiguration.safeParse({
        'participant.first_admin_invitation_ttl': 900000,
      }).success,
    ).toBe(false);
  });
  it('does not permit per-invitation TTL or runtime invocation capabilities', () => {
    const identifier = '018f0000-0000-7000-8000-000000000001';
    const proposal = {
      invitationId: identifier,
      mandateId: identifier,
      privacyDomainId: identifier,
      roleId: identifier,
      authorityEnvelopeId: identifier,
      assignmentId: identifier,
      displayName: 'Administrator',
      recipientIssuer: 'https://idp.example',
      recipientSubject: 'recipient',
      recipientAudience: 'openpc',
      tokenDigest: `sha256:${'a'.repeat(64)}`,
      actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
      configuration: {},
    };
    expect(firstAdministratorProposal.safeParse(proposal).success).toBe(true);
    expect(firstAdministratorProposal.safeParse({ ...proposal, ttlSeconds: 900 }).success).toBe(
      false,
    );
    expect(
      firstAdministratorProposal.safeParse({
        ...proposal,
        capabilityIds: ['SIGNED_TRANSACTION_SUBMISSION'],
      }).success,
    ).toBe(false);
    expect(
      firstAdministratorProposal.safeParse({
        ...proposal,
        actionIntentIds: [...proposal.actionIntentIds, ...proposal.actionIntentIds],
      }).success,
    ).toBe(false);
  });
});
