import { createHash } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import { identityEnvelopeSigningTrustDigest } from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { identityEnvelopeDualProofFixture } from '../../../participant-service/src/identity-envelope-rotation-proof.test-fixture.js';
import { recoveryFixtureId as id } from '../domain/identity-envelope-recovery.test-fixture.js';
import { publishIdentityEnvelopeRecoveryCutover } from './identity-envelope-recovery-rotation-cutover.js';
const owner = vi.hoisted(() => ({ source: vi.fn(), publish: vi.fn() }));
vi.mock('./identity-envelope-rotation-candidate.js', () => ({
  captureIdentityEnvelopeRotationSource: owner.source,
}));
vi.mock('./identity-envelope-recovery-rotation-prepare.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./identity-envelope-recovery-rotation-prepare.js')>()),
  resolveIdentityEnvelopeRecoveryRotationPhase: owner.publish,
}));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeDualProofFixture();
  if (!('kind' in f.input.admission)) throw Error();
  const { enrollment, lease } = f.input.admission;
  const operationId = id(750);
  const actor = {
    participantId: enrollment.participantId,
    principalId: lease.executorPrincipalId,
    platform: true,
    sessionToken: 'unit-only',
  };
  const step = {
    state: 'STARTED',
    current: true,
    bound: true,
    result: null as unknown,
    cbor: null as Buffer | null,
    digest: null as Buffer | null,
    cose: null as Buffer | null,
  };
  const prior = {
    operationId: f.input.operationId,
    expiresAtNs: f.records[0]!.request.challengeExpiresAtNs,
    attemptCount: 2,
  };
  let attemptCount = 0;
  const verified = {
    state: 'VERIFIED',
    admissionState: 'ADMITTED',
    signerId: f.trust.signerId,
    trustDigest: identityEnvelopeSigningTrustDigest(f.trust),
  };
  const selection = {
    signerId: verified.signerId,
    trustDigest: verified.trustDigest,
    selectionAdmissionVersion: '2',
    state: 'SELECTED',
  };
  const signer = {
    signCanonicalAssertion: vi.fn(async (payload: Buffer) => ({
      evidenceCbor: payload,
      evidenceDigest: createHash('sha256').update(payload).digest(),
      coseSign1: Buffer.from('unit-cose'),
    })),
    verifyCanonicalAssertion: vi.fn(async () => true),
  };
  const query = vi.fn(
    async (sql: string, params?: unknown[]): Promise<{ rowCount: number; rows: unknown[] }> => {
      if (sql.startsWith('select s.state')) return { rowCount: 1, rows: [step] };
      if (sql.startsWith('select s.operation_id')) return { rowCount: 1, rows: [prior] };
      if (sql.startsWith('select count')) return { rowCount: 1, rows: [{ count: attemptCount }] };
      if (sql.startsWith('select exists')) return { rowCount: 1, rows: [{ matches: true }] };
      if (sql.startsWith('select openpc.select_')) return { rowCount: 1, rows: [{ selection }] };
      if (sql.startsWith('update control.identity_envelope_rotation_step')) {
        step.state = 'COMMITTED';
        step.result = params![1];
        step.cbor = params![2] as Buffer;
        step.digest = params![3] as Buffer;
        step.cose = params![4] as Buffer;
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith('update') || sql.startsWith('insert')) return { rowCount: 1, rows: [] };
      throw Error('unexpected query');
    },
  );
  owner.source.mockResolvedValue({
    trust: f.input.oldTrust,
    issuer: f.input.currentIssuer,
    recordedAtNs: f.input.nowNs,
  });
  owner.publish.mockResolvedValue(verified);
  const publish = () =>
    publishIdentityEnvelopeRecoveryCutover(
      { query } as never,
      actor,
      enrollment,
      lease,
      operationId,
      true,
      signer as never,
    );
  return {
    ...f,
    enrollment,
    lease,
    operationId,
    actor,
    step,
    prior,
    verified,
    selection,
    signer,
    query,
    publish,
    extraAttempt: () => attemptCount++,
  };
}
const writes = (f: ReturnType<typeof fixture>) =>
  f.query.mock.calls.filter(([sql]) => /^(insert|update|select openpc.select_)/u.test(sql));
it('commits original versioned public cutover without any provider attempt, ordinary permission or old-key retirement', async () => {
  const f = fixture();
  expect(await f.publish()).toMatchObject({
    state: 'CUTOVER_FENCED',
    fromRevision: '5',
    revision: '6',
    selectionAdmissionVersion: '2',
    permissionEffect: 'NONE',
    observationsDigest: canonicalAuthorizationDigest([]),
  });
  const changed = writes(f);
  expect(changed.map(([sql]) => sql.split('\n')[0])).toEqual([
    expect.stringContaining('update control.identity_envelope_rotation_step'),
    expect.stringContaining('update control.signing_key_rotation'),
    expect.stringContaining('select openpc.select_identity_envelope_recovery_trust()'),
    expect.stringContaining('update control.outbox_aggregate_head'),
    expect.stringContaining('insert into control.outbox_event'),
  ]);
  expect(changed[1]?.[0]).toContain('cutover_at_ns=case');
  expect(
    changed.some(([sql]) =>
      /RETIRED|REVOKED|signing_provider|identity_envelope_activation/u.test(sql),
    ),
  ).toBe(false);
  expect(owner.publish).toHaveBeenCalledWith(
    expect.anything(),
    { kind: 'CURRENT', actor: f.actor },
    f.enrollment,
    f.lease,
    f.prior.operationId,
    true,
    f.signer,
  );
});
it('reads original committed cutover after lease expiry without changing the selection or recapturing issuer authority', async () => {
  const f = fixture();
  const result = await f.publish();
  f.query.mockClear();
  owner.source.mockClear();
  f.signer.signCanonicalAssertion.mockClear();
  f.step.current = false;
  expect(await f.publish()).toEqual(result);
  expect(writes(f)).toEqual([]);
  expect(owner.source).not.toHaveBeenCalled();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it('does not publish a stale original lease', async () => {
  const f = fixture();
  f.step.current = false;
  expect(await f.publish()).toBeUndefined();
  expect(writes(f)).toEqual([]);
  expect(owner.source).not.toHaveBeenCalled();
});
it.each([
  'executor',
  'bound',
  'proof-count',
  'extra-attempt',
  'unadmitted',
  'bad-verification',
  'expired-proof',
  'issuer-drift',
] as const)('denies %s before selection mutation', async (kind) => {
  const f = fixture();
  if (kind === 'executor') f.actor.principalId = f.lease.issuer.workloadPrincipalId;
  if (kind === 'bound') f.step.bound = false;
  if (kind === 'proof-count') f.prior.attemptCount = 1;
  if (kind === 'extra-attempt') f.extraAttempt();
  if (kind === 'bad-verification') owner.publish.mockRejectedValue(Error('bad original signature'));
  if (kind === 'unadmitted') f.verified.admissionState = 'ACTIVE';
  if (kind === 'expired-proof')
    owner.source.mockResolvedValue({
      trust: f.input.oldTrust,
      issuer: f.input.currentIssuer,
      recordedAtNs: BigInt(f.prior.expiresAtNs),
    });
  if (kind === 'issuer-drift')
    owner.source.mockResolvedValue({
      trust: f.input.oldTrust,
      issuer: { ...f.input.currentIssuer, workloadPrincipalEpoch: '3' },
      recordedAtNs: f.input.nowNs,
    });
  await expect(f.publish()).rejects.toThrow();
  expect(writes(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['version', 'signature', 'event', 'result'] as const)(
  'rejects altered historical cutover %s without a new selection',
  async (kind) => {
    const f = fixture();
    await f.publish();
    f.query.mockClear();
    if (kind === 'signature') f.signer.verifyCanonicalAssertion.mockResolvedValue(false);
    if (kind === 'version')
      f.step.result = { ...(f.step.result as object), selectionAdmissionVersion: '3' };
    if (kind === 'result')
      f.step.result = { ...(f.step.result as object), permissionEffect: 'CALL' };
    if (kind === 'event') {
      const original = f.query.getMockImplementation()!;
      f.query.mockImplementation((sql, params) =>
        sql.startsWith('select exists')
          ? Promise.resolve({ rowCount: 1, rows: [{ matches: false }] })
          : original(sql, params),
      );
    }
    await expect(f.publish()).rejects.toThrow();
    expect(writes(f)).toEqual([]);
  },
);
it.each(['selector', 'result', 'rotation-cas', 'outbox-cas'] as const)(
  'propagates %s failure for the enclosing rollback',
  async (kind) => {
    const f = fixture();
    const original = f.query.getMockImplementation()!;
    if (kind === 'result') f.selection.selectionAdmissionVersion = '3';
    f.query.mockImplementation((sql, params) => {
      if (kind === 'selector' && sql.startsWith('select openpc.select_'))
        throw Error('selection denied');
      if (
        (kind === 'rotation-cas' && sql.startsWith('update control.signing_key_rotation')) ||
        (kind === 'outbox-cas' && sql.startsWith('update control.outbox_aggregate_head'))
      )
        return Promise.resolve({ rowCount: 0, rows: [] });
      return original(sql, params);
    });
    await expect(f.publish()).rejects.toThrow();
    expect(writes(f).some(([sql]) => sql.startsWith('insert into control.outbox_event'))).toBe(
      false,
    );
  },
);
