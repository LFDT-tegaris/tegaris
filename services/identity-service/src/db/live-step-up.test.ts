import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import { AuthorityFenceError } from './authority-fence.js';
import { lockLiveStepUpRecord, type LiveStepUpRecord } from './live-step-up.js';

const binding = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  principalId: '018f0000-0000-7000-8000-000000000111',
  sessionId: '01a0ef94-0433-7e5b-970c-57c7ab19375e',
  participantEpoch: '1',
  principalEpoch: '1',
  actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
  resourceDigest: Buffer.alloc(32, 1),
  resourceId: '01a0ef70-abc1-72ea-9d66-e995cd8b336c',
  operationId: '01a0efbd-c415-7c9d-9d7a-ff4f13f31472',
};

function record(challenge: string, credential = '01a0ef17-c296-7d3f-aaad-f25289f36e36') {
  return {
    mfaChallengeId: challenge,
    signerCredentialId: credential,
    signerCredentialEpoch: '1',
    evidenceCbor: Buffer.alloc(1),
    evidenceDigest: Buffer.alloc(32),
    coseSign1: Buffer.alloc(1),
    assertionBindingDigest: Buffer.alloc(32),
    credentialPublicKey: Buffer.alloc(1),
  } satisfies LiveStepUpRecord;
}

describe('live step-up selection', () => {
  it('uses the newest exact proof when repeated assertions use one credential', async () => {
    const newest = record('01a0efbd-c415-7c9d-9d7a-ff4f13f31472');
    const earlier = record('01a0efbd-b137-78a1-92d7-06ea3e489e25');
    const client = {
      query: vi.fn().mockResolvedValue({ rowCount: 2, rows: [newest, earlier] }),
    } as unknown as PoolClient;

    await expect(lockLiveStepUpRecord(client, binding)).resolves.toBe(newest);
  });

  it('rejects otherwise matching proofs from different credentials', async () => {
    const client = {
      query: vi.fn().mockResolvedValue({
        rowCount: 2,
        rows: [
          record('01a0efbd-c415-7c9d-9d7a-ff4f13f31472'),
          record('01a0efbd-b137-78a1-92d7-06ea3e489e25', '01a0ef17-c296-7d3f-aaad-f25289f36e37'),
        ],
      }),
    } as unknown as PoolClient;

    await expect(lockLiveStepUpRecord(client, binding)).rejects.toBeInstanceOf(AuthorityFenceError);
  });
});
