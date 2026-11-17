import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import { platformEnvelopeRevocationPolicyScope } from './platform-envelope-revocation-policy.js';

const participantId = '018f0000-0000-7000-8000-000000000101';
const principalId = '018f0000-0000-7000-8000-000000000111';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const envelopeId = '01a0f079-1648-72ac-abe1-c0aa60dd66c3';
const digest = `sha256:${'a'.repeat(64)}`;
const document = { envelopeId, reason: 'Retain only the narrower successor envelope.' };

describe('Platform envelope revocation policy scope', () => {
  it('admits the exact active Platform-root target for candidate staging', async () => {
    const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [{ '?column?': 1 }] });
    await expect(
      platformEnvelopeRevocationPolicyScope(
        { query } as unknown as PoolClient,
        participantId,
        principalId,
        {
          sessionToken: 'session',
          privacyDomainId,
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          catalogOperationId: 'ID-OP-ENVELOPE-REVOKE',
          resourceId: envelopeId,
          stepUpRequired: false,
        },
      ),
    ).resolves.toBe(true);
    expect(query).toHaveBeenCalledWith(expect.stringContaining("envelope.state='ACTIVE'"), [
      participantId,
      privacyDomainId,
      envelopeId,
      null,
    ]);
  });

  it('denies a foreign or inactive target before staging', async () => {
    const query = vi.fn().mockResolvedValue({ rowCount: 0, rows: [] });
    await expect(
      platformEnvelopeRevocationPolicyScope(
        { query } as unknown as PoolClient,
        participantId,
        principalId,
        {
          sessionToken: 'session',
          privacyDomainId,
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          catalogOperationId: 'ID-OP-ENVELOPE-REVOKE',
          resourceId: envelopeId,
          stepUpRequired: false,
        },
      ),
    ).resolves.toBe(false);
  });

  it('binds approval creation to the current exact candidate and revision', async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({
        rowCount: 1,
        rows: [{ envelopeId, expectedRevision: '4', document, live: true }],
      })
      .mockResolvedValueOnce({ rowCount: 1, rows: [{ '?column?': 1 }] });
    await expect(
      platformEnvelopeRevocationPolicyScope(
        { query } as unknown as PoolClient,
        participantId,
        principalId,
        {
          sessionToken: 'session',
          privacyDomainId,
          actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
          resourceId: principalId,
          approvalCandidateDigest: digest,
          stepUpRequired: false,
        },
      ),
    ).resolves.toBe(true);
    expect(query).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('envelope.row_version=$4::bigint'),
      [participantId, privacyDomainId, envelopeId, '4'],
    );
  });

  it('denies mismatched candidate documents and unrelated actions', async () => {
    const query = vi.fn().mockResolvedValueOnce({
      rowCount: 1,
      rows: [
        {
          envelopeId,
          expectedRevision: '4',
          document: { ...document, envelopeId: '01a0f079-1648-72ac-abe1-c0aa60dd66c4' },
          live: true,
        },
      ],
    });
    await expect(
      platformEnvelopeRevocationPolicyScope(
        { query } as unknown as PoolClient,
        participantId,
        principalId,
        {
          sessionToken: 'session',
          privacyDomainId,
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          resourceId: envelopeId,
          stepUpCandidateDigest: digest,
          stepUpRequired: false,
        },
      ),
    ).resolves.toBe(false);
    await expect(
      platformEnvelopeRevocationPolicyScope(
        { query: vi.fn() } as unknown as PoolClient,
        participantId,
        principalId,
        {
          sessionToken: 'session',
          privacyDomainId,
          actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
          resourceId: envelopeId,
          stepUpRequired: false,
        },
      ),
    ).resolves.toBeUndefined();
  });
});
