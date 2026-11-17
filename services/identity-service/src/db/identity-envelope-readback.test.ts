import type { PoolClient, QueryResult } from 'pg';
import { describe, expect, it } from 'vitest';
import { AuthorityFenceError } from './authority-fence.js';
import { readEnvelopeEffectReadback } from './identity-envelope-readback.js';

const operationId = '018f0000-0000-7000-8000-000000000401';
const creation = {
  stored: {
    state: 'APPROVED',
    version: '3',
    envelopeId: '018f0000-0000-7000-8000-000000000301',
    digest: Buffer.alloc(32, 7),
  },
  original: { operationId: '018f0000-0000-7000-8000-000000000201' },
} as unknown as Parameters<typeof readEnvelopeEffectReadback>[2];
const scope = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000102',
};

function client(rows: readonly { id: string }[], rowCount = rows.length): PoolClient {
  return {
    query: async (text: string, values: readonly unknown[]) => {
      expect(text).toContain("activation.state='COMMITTED'");
      expect(text).toContain("candidate.state='CONSUMED'");
      expect(text).toContain("receipt.terminal_state='COMMITTED'");
      expect(text).toContain("evidence.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE'");
      expect(values).toEqual([
        scope.participantId,
        scope.privacyDomainId,
        creation.stored.envelopeId,
        creation.stored.digest,
      ]);
      return { rows: [...rows], rowCount } as QueryResult<{ id: string }>;
    },
  } as unknown as PoolClient;
}

describe('activated envelope readback', () => {
  it('returns the one fully bound committed activation operation', async () => {
    await expect(
      readEnvelopeEffectReadback(client([{ id: operationId }]), scope, creation),
    ).resolves.toEqual({ operationId, state: 'ACTIVE', version: '4' });
  });

  it('fails closed when the committed activation history is ambiguous', async () => {
    await expect(
      readEnvelopeEffectReadback(
        client([{ id: operationId }, { id: operationId }]),
        scope,
        creation,
      ),
    ).rejects.toBeInstanceOf(AuthorityFenceError);
  });
});
