import { createHash } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
import { closeIdentityEnvelopeRecoveryCase } from './identity-envelope-recovery-closure.js';

function fixture(failure?: string) {
  const f = identityEnvelopeRecoveryFixture();
  const query = vi.fn(async (sql: string, _values: unknown[]) => {
    if (sql.startsWith('update control.platform_recovery_case'))
      return {
        rowCount: failure === 'conflict' ? 0 : 1,
        rows: [{ state: 'REVOKED', revision: '4', now: f.now }],
      };
    if (sql.startsWith('insert into control.outbox_aggregate_head'))
      return { rowCount: failure === 'head' ? 0 : 1, rows: [{ sequence: '2' }] };
    if (sql.startsWith('insert into control.outbox_event')) {
      if (failure === 'outbox') throw Error('outbox unavailable');
      return { rowCount: 1, rows: [] };
    }
    throw Error('unexpected query');
  });
  const signer = {
    signCanonicalAssertion: vi.fn(async (payload: Buffer) => ({
      evidenceCbor: failure === 'bytes' ? Buffer.alloc(0) : payload,
      evidenceDigest: createHash('sha256').update(payload).digest(),
      coseSign1: Buffer.from('unit-only'),
      signerKeyDigest: Buffer.alloc(32, 1),
    })),
    verifyCanonicalAssertion: vi.fn(async () =>
      failure === 'signature' ? undefined : { signerKeyDigest: Buffer.alloc(32, 1) },
    ),
  };
  const actor = {
    participantId: f.enrollment.participantId,
    principalId: f.enrollment.recoveryPrincipal.principalId,
    platform: true,
    sessionToken: 'unit-only',
  };
  const close = () =>
    closeIdentityEnvelopeRecoveryCase(
      { query } as never,
      actor,
      f.enrollment,
      id(400),
      '3',
      { sessionId: id(800), sessionEpoch: '1' },
      id(900),
      signer,
    );
  return { ...f, actor, query, signer, close };
}
it.each(['executor', 'custodian'])(
  'allows the enrolled %s to close the exact case while preserving signed activation and review debt',
  async (role) => {
    const f = fixture();
    if (role === 'custodian') f.actor.principalId = f.enrollment.custodians[0].principalId;
    await f.close();
    const mutation = f.query.mock.calls[0]![0];
    expect(mutation).toContain("state in ('DRAFT','REQUESTED','ACTIVE')");
    expect(mutation).not.toMatch(/set[^]*\b(activated_at|lease_bindings|reviewed_at)\s*=/u);
    expect(f.query.mock.calls[0]![1]).toEqual([
      f.actor.participantId,
      f.enrollment.enrollmentId,
      id(400),
      '3',
    ]);
    expect(f.query.mock.calls[2]![0]).toContain('openpc.identity.envelope-recovery.closed.v1');
    expect(f.query.mock.calls[2]![1][3]).toBe('2');
    expect(
      f.query.mock.calls.some(([sql]) =>
        /control\.(principal|session|assignment|authority_envelope|business_signing_key)\b/u.test(
          sql,
        ),
      ),
    ).toBe(false);
  },
);
it('rejects an unenrolled administrator before closure or signing', async () => {
  const f = fixture();
  f.actor.principalId = f.enrollment.administratorPrincipalIds[0];
  await expect(f.close()).rejects.toThrow();
  expect(f.query).not.toHaveBeenCalled();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['conflict', 'bytes', 'signature', 'head', 'outbox'])(
  'propagates %s so the owning transaction cannot commit partial closure',
  async (failure) => {
    await expect(fixture(failure).close()).rejects.toThrow();
  },
);
