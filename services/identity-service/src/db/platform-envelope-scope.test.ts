import { describe, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import {
  encodeEnvelopeScope,
  platformEnvelopeScopeDigest,
  platformEnvelopeScopePreimage,
  platformEnvelopeScopeSuccessorDigest,
  platformEnvelopeScopeSuccessorPreimage,
} from '@openpc/security-kernel';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';

function fixture(epoch = '1') {
  const admission = {
    platformContextId: id(4),
    ownerParticipantId: id(1),
    installationPrivacyDomainId: id(2),
    platformAuthorityEpoch: epoch,
    environmentId: 'platform-test',
    installationDigest: digest(1),
    grantable: envelopeFixtureScope(),
  };
  const successor = {
    admission,
    replacementId: id(10),
    preparationOperationId: id(11),
    predecessorEpoch: '1',
    predecessorDigest: digest(2),
  };
  const row = {
    platform_context_id: admission.platformContextId,
    owner_participant_id: admission.ownerParticipantId,
    installation_privacy_domain_id: admission.installationPrivacyDomainId,
    platform_authority_epoch: epoch,
    environment_id: admission.environmentId,
    installation_digest: admission.installationDigest,
    scope_cbor: encodeEnvelopeScope(admission.grantable),
    admission_preimage:
      epoch === '1'
        ? platformEnvelopeScopePreimage(admission)
        : platformEnvelopeScopeSuccessorPreimage(successor),
    admission_digest: Buffer.from(
      (epoch === '1'
        ? platformEnvelopeScopeDigest(admission)
        : platformEnvelopeScopeSuccessorDigest(successor)
      ).slice(7),
      'hex',
    ),
    replacement_id: epoch === '1' ? null : successor.replacementId,
    prepare_operation_id: epoch === '1' ? null : successor.preparationOperationId,
    predecessor_epoch: epoch === '1' ? null : successor.predecessorEpoch,
    predecessor_digest:
      epoch === '1' ? null : Buffer.from(successor.predecessorDigest.slice(7), 'hex'),
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [row] });
  const client = { query } as unknown as PoolClient;
  return { admission, row, client, query };
}

describe('effective Platform ceiling selection', () => {
  it.each(['1', '2'])('validates the immutable source for current epoch %s', async (epoch) => {
    const { admission, client, query } = fixture(epoch);
    const actual = await readCurrentPlatformScope(client, id(4), epoch);
    expect(actual).toMatchObject(admission);
    expect(query).toHaveBeenCalledWith(expect.stringContaining("p.state='ACTIVE'"), [id(4), epoch]);
    const sql = query.mock.calls[0]![0] as string;
    expect(sql).toContain('openpc.lock_platform_scope_context($1)');
    expect(sql).not.toContain('for share of p');
  });
  it('does not reinterpret a successor as an installation source', async () => {
    const { row, client } = fixture('2');
    row.replacement_id = null;
    await expect(readCurrentPlatformScope(client, id(4), '2')).rejects.toThrow();
  });
  it.each(['root', 'epoch', 'scope', 'predecessor', 'preparation', 'digest'])(
    'rejects %s drift',
    async (field) => {
      const { row, client } = fixture('2');
      if (field === 'root') row.platform_context_id = id(6);
      if (field === 'epoch') row.platform_authority_epoch = '3';
      if (field === 'scope')
        row.scope_cbor = encodeEnvelopeScope({ ...envelopeFixtureScope(), stepUpRequired: false });
      if (field === 'predecessor') row.predecessor_digest = Buffer.from(digest(9).slice(7), 'hex');
      if (field === 'preparation') row.prepare_operation_id = id(12);
      if (field === 'digest') row.admission_digest = Buffer.from(digest(9).slice(7), 'hex');
      await expect(readCurrentPlatformScope(client, id(4), '2')).rejects.toThrow();
    },
  );
  it.each([0, 2])('fails closed on missing or ambiguous durable source (%i)', async (rowCount) => {
    const { client, query, row } = fixture();
    query.mockResolvedValue({ rowCount, rows: rowCount ? [row, row] : [] });
    await expect(readCurrentPlatformScope(client, id(4))).rejects.toThrow();
  });
});
