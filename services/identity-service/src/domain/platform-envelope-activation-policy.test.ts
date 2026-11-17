import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import { platformEnvelopeActivationPolicyScope } from './platform-envelope-activation-policy.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const principalId = '018f0000-0000-7000-8000-000000000111';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const envelopeId = '01a0ef70-abc1-72ea-9d66-e995cd8b336c';
const approvalId = '01a0ef76-20c1-7470-9fd2-bf58eeccc3d6';

vi.mock('@openpc/security-kernel', () => ({
  decodeEnvelopeProposal: vi.fn(() => ({
    issuance: 'PLATFORM_ROOT',
    participantId,
    issuer: { authority: { participantId } },
  })),
}));

vi.mock('../db/identity-envelope-proposal.js', () => ({
  findEnvelopeProposal: vi.fn(async () => ({
    envelopeId,
    state: 'APPROVED',
    version: '3',
    bytes: new Uint8Array(),
  })),
}));

describe('Platform envelope activation approval recovery', () => {
  it('selects only the current successor for action-bound WebAuthn', async () => {
    const candidateDigest = `sha256:${'a'.repeat(64)}`;
    const query = vi
      .fn()
      .mockResolvedValueOnce({
        rowCount: 1,
        rows: [
          {
            envelopeId,
            document: { envelopeId },
            digest: Buffer.from(candidateDigest.slice(7), 'hex'),
            live: true,
          },
        ],
      })
      .mockResolvedValueOnce({ rowCount: 1, rows: [{ digest: Buffer.alloc(32, 1) }] });

    await expect(
      platformEnvelopeActivationPolicyScope(
        { query } as unknown as PoolClient,
        participantId,
        principalId,
        {
          sessionToken: 'session',
          privacyDomainId,
          actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
          resourceId: envelopeId,
          stepUpCandidateDigest: candidateDigest,
          stepUpRequired: false,
        },
      ),
    ).resolves.toBe(true);
    expect(query.mock.calls[0]?.[0]).toContain('and (not ($5 or $6) or not exists');
  });

  it('admits the exact maker update for a resumable activation approval', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({
        rowCount: 1,
        rows: [
          {
            envelopeId,
            document: { envelopeId },
            digest: Buffer.alloc(32, 2),
            live: true,
          },
        ],
      })
      .mockResolvedValueOnce({ rowCount: 1, rows: [{ digest: Buffer.alloc(32, 1) }] });

    await expect(
      platformEnvelopeActivationPolicyScope(
        { query } as unknown as PoolClient,
        participantId,
        principalId,
        {
          sessionToken: 'session',
          privacyDomainId,
          actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
          resourceId: approvalId,
          stepUpRequired: false,
        },
      ),
    ).resolves.toBe(true);
    expect(query).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining("$7='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'"),
      [
        participantId,
        privacyDomainId,
        approvalId,
        principalId,
        false,
        false,
        'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        null,
      ],
    );
    expect(query.mock.calls[0]?.[0]).not.toContain(
      "c.state in ('APPROVAL_REQUESTED','APPROVED','EXPIRED')",
    );
  });

  it('denies an update when the exact activation candidate is not resumable', async () => {
    const query = vi.fn().mockResolvedValueOnce({
      rowCount: 1,
      rows: [
        {
          envelopeId,
          document: { envelopeId },
          digest: Buffer.alloc(32, 2),
          live: false,
        },
      ],
    });

    await expect(
      platformEnvelopeActivationPolicyScope(
        { query } as unknown as PoolClient,
        participantId,
        principalId,
        {
          sessionToken: 'session',
          privacyDomainId,
          actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
          resourceId: approvalId,
          stepUpRequired: false,
        },
      ),
    ).resolves.toBe(false);
  });
});
