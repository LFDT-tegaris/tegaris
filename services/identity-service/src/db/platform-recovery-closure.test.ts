import { createHash } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import { platformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { closePlatformRecoveryCase } from './platform-recovery-closure.js';

function setup(failure?: string) {
  const { source, intent } = platformRecoveryFixture();
  const query = vi.fn(async (sql: string) => {
    if (sql.startsWith('update control.platform_recovery_case'))
      return {
        rowCount: failure === 'conflict' ? 0 : 1,
        rows: [{ state: 'REVOKED', revision: '3', now: source.now }],
      };
    if (sql.startsWith('insert into control.outbox_aggregate_head'))
      return { rowCount: 1, rows: [{ sequence: '2' }] };
    if (sql.startsWith('insert into control.outbox_event')) {
      if (failure === 'outbox') throw new Error('outbox unavailable');
      return { rowCount: 1, rows: [] };
    }
    throw new Error('Unexpected closure query');
  });
  const signer = {
    signCanonicalAssertion: vi.fn(async (payload: Buffer) => ({
      evidenceCbor: failure === 'bytes' ? Buffer.alloc(0) : payload,
      evidenceDigest: createHash('sha256').update(payload).digest(),
      coseSign1: Buffer.alloc(64),
      signerKeyDigest: Buffer.alloc(32),
    })),
    verifyCanonicalAssertion: vi.fn(async () =>
      failure === 'signature' ? undefined : { signerKeyDigest: Buffer.alloc(32) },
    ),
  };
  const actor = {
    principalId: source.enrollment.recoveryPrincipal.principalId,
    participantId: source.enrollment.participantId,
    platform: true,
    sessionToken: 'mocked-session',
  };
  return { query, client: { query } as never, source, intent, signer, actor };
}
function close(v: ReturnType<typeof setup>) {
  return closePlatformRecoveryCase(
    v.client,
    v.actor,
    v.source.enrollment,
    v.intent.recoveryId,
    '2',
    { sessionId: id(800), sessionEpoch: '1' },
    id(900),
    v.signer,
  );
}
it('closes the original case with one sequenced signed event and no lease or identity mutation', async () => {
  const v = setup();
  await close(v);
  expect(v.query).toHaveBeenCalledTimes(3);
  expect(v.signer.signCanonicalAssertion).toHaveBeenCalledOnce();
  expect(
    v.query.mock.calls.some(([sql]) =>
      /control\.(assignment|authority_envelope|principal|session)\b/u.test(sql),
    ),
  ).toBe(false);
});
it.each(['conflict', 'bytes', 'signature', 'outbox'])(
  'propagates %s so the caller transaction rolls back closure',
  async (failure) => {
    await expect(close(setup(failure))).rejects.toThrow();
  },
);
