import { expect, it } from 'vitest';
import { contextAdmitted } from './local-governance-api';
import type { IdentitySession } from './local-runtime';

it('admits actual selected Participant contexts beyond the old fixture IDs and rejects Platform or incomplete contexts', () => {
  for (const suffix of ['101', '102']) {
    const session = {
      participantId: `018f0000-0000-7000-8000-000000000${suffix}`,
      privacyDomainId: `018f0000-0000-7000-8000-000000000${suffix === '101' ? '201' : '202'}`,
      principalId: '018f0000-0000-7000-8000-000000000111',
      contextMode: 'PARTICIPANT',
    } as IdentitySession;
    expect(contextAdmitted(session)).toBe(true);
    expect(contextAdmitted({ ...session, contextMode: 'PLATFORM' })).toBe(false);
    expect(contextAdmitted({ ...session, privacyDomainId: undefined })).toBe(false);
    expect(contextAdmitted({ ...session, participantId: 'unverified' })).toBe(false);
  }
});
