import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';

import { platformEnvelopePolicyScope } from './platform-envelope-policy.js';

vi.mock('./platform-envelope-activation-policy.js', () => ({
  platformEnvelopeActivationPolicyScope: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('./platform-envelope-revocation-policy.js', () => ({
  platformEnvelopeRevocationPolicyScope: vi.fn().mockResolvedValue(undefined),
}));

const participantId = '018f0000-0000-7000-8000-000000000101';
const principalId = '018f0000-0000-7000-8000-000000000111';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const resourceId = '018f0000-0000-7000-8000-000000000501';
const digest = `sha256:${'a'.repeat(64)}`;

it('permits only a bound Platform actor to obtain the pre-staging envelope challenge', async () => {
  for (const bound of [true, false]) {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rowCount: 0, rows: [] })
      .mockResolvedValueOnce({ rowCount: 0, rows: [] })
      .mockResolvedValueOnce({ rowCount: bound ? 1 : 0, rows: bound ? [{}] : [] });
    const result = await platformEnvelopePolicyScope(
      { query } as unknown as PoolClient,
      participantId,
      principalId,
      {
        sessionToken: 'session',
        privacyDomainId,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceId,
        stepUpCandidateDigest: digest,
        stepUpRequired: false,
      },
    );
    expect(result).toBe(bound);
    expect(query).toHaveBeenNthCalledWith(
      3,
      expect.stringContaining('from control.platform_envelope_scope'),
      [participantId, principalId, privacyDomainId, resourceId],
    );
  }
});

it('does not admit a malformed pre-staging candidate binding', async () => {
  const query = vi.fn().mockResolvedValue({ rowCount: 0, rows: [] });
  await expect(
    platformEnvelopePolicyScope({ query } as unknown as PoolClient, participantId, principalId, {
      sessionToken: 'session',
      privacyDomainId,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      resourceId,
      stepUpCandidateDigest: 'not-a-digest',
      stepUpRequired: false,
    }),
  ).resolves.toBe(false);
});

it.each([true, false])(
  'uses the exact stored current envelope-create attempt for fresh-session continuation (live=%s)',
  async (live) => {
    const { envelopeFixtureId, envelopeFixtureScope } =
      await import('../../../../packages/security-kernel/src/identity-envelope/fixture.js');
    const scope = envelopeFixtureScope();
    const document = {
      schema: 'pc.identity.authority-envelope-proposal',
      schemaVersion: 1,
      envelopeId: envelopeFixtureId(60),
      id: envelopeFixtureId(60),
      participantId,
      state: 'DRAFT',
      issuance: 'PLATFORM_ROOT',
      usable: scope,
      grantable: scope,
    };
    const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [{ document, live }] });
    const result = await platformEnvelopePolicyScope(
      { query } as unknown as PoolClient,
      participantId,
      principalId,
      {
        sessionToken: 'fresh-session',
        privacyDomainId,
        actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        resourceId,
        stepUpRequired: false,
      },
    );
    expect(result).toBe(live);
    expect(query).toHaveBeenCalledWith(expect.stringContaining('c.maker_principal_id=$5'), [
      participantId,
      privacyDomainId,
      resourceId,
      'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
      principalId,
    ]);
    expect(query.mock.calls[0]![0]).toContain(
      'successor.predecessor_candidate_id=c.mutation_candidate_id',
    );
    expect(query.mock.calls[0]![0]).toContain('c.consumed_operation_id is null');
  },
);
it('selects only the current creation attempt for post-resume WebAuthn instead of ambiguous historical bodies', async () => {
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 0, rows: [] })
    .mockResolvedValueOnce({ rowCount: 0, rows: [] })
    .mockResolvedValueOnce({ rowCount: 0, rows: [] });
  await platformEnvelopePolicyScope(
    { query } as unknown as PoolClient,
    participantId,
    principalId,
    {
      sessionToken: 'fresh-session',
      privacyDomainId,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      resourceId,
      stepUpCandidateDigest: digest,
      stepUpRequired: false,
    },
  );
  expect(query.mock.calls[0]![0]).toContain(
    'successor.predecessor_candidate_id=c.mutation_candidate_id',
  );
});

it.each([1, 2])(
  'delegates only an unambiguous original custody-change challenge to its owning handler (matches=%s)',
  async (matches) => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rowCount: 0, rows: [] })
      .mockResolvedValueOnce({
        rowCount: matches,
        rows: Array.from({ length: matches }, () => ({})),
      });
    await expect(
      platformEnvelopePolicyScope({ query } as unknown as PoolClient, participantId, principalId, {
        sessionToken: 'session',
        privacyDomainId,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceId,
        stepUpCandidateDigest: digest,
        stepUpRequired: false,
      }),
    ).resolves.toBe(matches === 1 ? undefined : false);
    expect(query).toHaveBeenCalledTimes(2);
    const [sql, values] = query.mock.calls[1]!;
    expect(values).toEqual([
      participantId,
      privacyDomainId,
      resourceId,
      principalId,
      Buffer.from('a'.repeat(64), 'hex'),
    ]);
    expect(sql).toContain('maker_principal_id=$4 and candidate_digest=$5');
    expect(sql).toContain('consumed_operation_id is null and expires_at>clock_timestamp()');
    expect(sql).toContain('successor.predecessor_candidate_id=c.mutation_candidate_id');
  },
);

it('keeps an envelope subject denial with its original owner instead of delegating', async () => {
  const query = vi.fn().mockResolvedValueOnce({
    rowCount: 1,
    rows: [{ document: {}, digest, live: false }],
  });
  await expect(
    platformEnvelopePolicyScope({ query } as unknown as PoolClient, participantId, principalId, {
      sessionToken: 'session',
      privacyDomainId,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      resourceId,
      stepUpCandidateDigest: digest,
      stepUpRequired: false,
    }),
  ).resolves.toBe(false);
  expect(query).toHaveBeenCalledTimes(1);
});
