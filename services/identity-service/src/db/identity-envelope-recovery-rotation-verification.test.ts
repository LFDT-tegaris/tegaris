import { createHash } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import {
  identityEnvelopeSigningTrustPreimage,
  identityEnvelopeSigningTrustDigest,
} from '@openpc/security-kernel';
import { identityEnvelopeDualProofFixture } from '../../../participant-service/src/identity-envelope-rotation-proof.test-fixture.js';
import { publishIdentityEnvelopeRecoveryVerification } from './identity-envelope-recovery-rotation-verification.js';
import { identityEnvelopeRotationRequestDigest } from '../domain/identity-envelope-rotation-provider.js';
const owner = vi.hoisted(() => ({ source: vi.fn(), creation: vi.fn(), distributed: vi.fn() }));
vi.mock('./identity-envelope-rotation-candidate.js', () => ({
  captureIdentityEnvelopeRotationSource: owner.source,
}));
vi.mock('./identity-envelope-recovery-rotation.js', () => ({
  authenticateIdentityEnvelopeRecoveryRotationCreation: owner.creation,
}));
vi.mock('./identity-envelope-recovery-rotation-prepare.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./identity-envelope-recovery-rotation-prepare.js')>()),
  resolveIdentityEnvelopeRecoveryDistributedDescriptor: owner.distributed,
}));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeDualProofFixture();
  const admission = f.input.admission;
  if (!('kind' in admission)) throw Error();
  const { enrollment, lease } = admission;
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
  const attempts = f.records.map((r) => ({
    ...r,
    state: 'OBSERVED',
    requestDigest: Buffer.from(identityEnvelopeRotationRequestDigest(r.request).slice(7), 'hex'),
    firstDigest: canonicalAuthorizationDigestBytes(r.firstObservation),
    digest: canonicalAuthorizationDigestBytes(r.observation),
    startedAtNs: r.request.challengeIssuedAtNs,
  }));
  const trust = f.input.oldTrust;
  const oldRow = {
    participant_id: trust.participantId,
    privacy_domain_id: trust.privacyDomainId,
    environment_id: trust.environmentId,
    signer_id: trust.signerId,
    public_key_spki_der: trust.publicKeySpkiDer,
    workload_credential_id: trust.workloadCredentialId,
    workload_credential_epoch: '1',
    key_epoch: '1',
    envelope_workload_participant_epoch: '1',
    envelope_workload_principal_epoch: '1',
    valid_from_ns: trust.validFromNs.toString(),
    valid_until_ns: trust.validUntilNs.toString(),
    admission_kind: trust.admissionKind,
    admission_reference: trust.admissionReference,
    admission_digest: trust.admissionDigest,
    secret_class: trust.secretClass,
    secret_reference: trust.secretReference,
    secret_version: trust.secretVersion,
    trust_preimage: identityEnvelopeSigningTrustPreimage(trust),
    trust_digest: Buffer.from(identityEnvelopeSigningTrustDigest(trust).slice(7), 'hex'),
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
      if (sql.includes('from control.identity_envelope_rotation_step s'))
        return { rowCount: 1, rows: [step] };
      if (sql.includes('from control.identity_envelope_rotation_attempt where'))
        return { rowCount: attempts.length, rows: attempts };
      if (sql.startsWith('select key.*')) return { rowCount: 1, rows: [oldRow] };
      if (sql.startsWith('select exists')) return { rowCount: 1, rows: [{ matches: true }] };
      if (sql.startsWith('select openpc.admit_'))
        return {
          rowCount: 1,
          rows: [
            {
              admission: {
                signerId: f.trust.signerId,
                trustDigest: identityEnvelopeSigningTrustDigest(f.trust),
                state: 'ADMITTED',
              },
            },
          ],
        };
      if (sql.startsWith('update control.identity_envelope_rotation_step')) {
        step.state = 'COMMITTED';
        step.result = params![1];
        step.cbor = params![2] as Buffer;
        step.digest = params![3] as Buffer;
        step.cose = params![4] as Buffer;
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith('update') || sql.startsWith('insert')) return { rowCount: 1, rows: [] };
      throw new Error('unexpected query');
    },
  );
  owner.source.mockResolvedValue({
    trust,
    currentIssuer: f.input.currentIssuer,
    issuer: f.input.currentIssuer,
    recordedAtNs: f.input.nowNs + 123000n,
  });
  owner.distributed.mockResolvedValue({
    descriptor: f.input.descriptor,
    result: { state: 'DISTRIBUTED', trustDigest: identityEnvelopeSigningTrustDigest(f.trust) },
  });
  const publish = () =>
    publishIdentityEnvelopeRecoveryVerification(
      { query } as never,
      actor,
      enrollment,
      lease,
      f.input.operationId,
      true,
      signer as never,
    );
  return { ...f, actor, enrollment, lease, step, attempts, signer, query, publish };
}
const writes = (f: ReturnType<typeof fixture>) =>
  f.query.mock.calls.filter(([sql]) => /^(insert|update|select openpc.admit_)/u.test(sql));
it('publishes exact real dual proof and public ADMITTED trust in the original result/state/admission/outbox order', async () => {
  const f = fixture();
  const result = await f.publish();
  expect(result).toMatchObject({
    state: 'VERIFIED',
    admissionState: 'ADMITTED',
    fromRevision: '4',
    revision: '5',
    trustDigest: identityEnvelopeSigningTrustDigest(f.trust),
  });
  expect(result?.completedAt).toMatch(/123000Z$/u);
  const changed = writes(f);
  expect(changed.map(([sql]) => sql.split('\n')[0])).toEqual([
    expect.stringContaining('update control.identity_envelope_rotation_step'),
    expect.stringContaining('update control.signing_key_rotation'),
    expect.stringContaining('select openpc.admit_identity_envelope_recovery_trust'),
    expect.stringContaining('update control.outbox_aggregate_head'),
    expect.stringContaining('insert into control.outbox_event'),
  ]);
  expect(changed[2]?.[1]).toEqual([
    identityEnvelopeSigningTrustPreimage(f.trust),
    Buffer.from(identityEnvelopeSigningTrustDigest(f.trust).slice(7), 'hex'),
  ]);
  expect(
    changed.some(([sql]) => /selection|RETIRED|REVOKED|identity_envelope_activation/u.test(sql)),
  ).toBe(false);
});
it('authenticates committed evidence after lease expiry without recapturing current authority or writing again', async () => {
  const f = fixture();
  const result = await f.publish();
  f.step.current = false;
  f.input.nowNs = f.input.authorityValidUntilNs + 1n;
  f.query.mockClear();
  f.signer.signCanonicalAssertion.mockClear();
  owner.source.mockClear();
  owner.creation.mockClear();
  expect(await f.publish()).toEqual(result);
  expect(writes(f)).toEqual([]);
  expect(owner.source).not.toHaveBeenCalled();
  expect(owner.creation).not.toHaveBeenCalled();
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each(['pending', 'stale'] as const)('keeps %s proof unpublished', async (kind) => {
  const f = fixture();
  if (kind === 'pending') f.attempts[1]!.state = 'STARTED';
  else f.step.current = false;
  expect(await f.publish()).toBeUndefined();
  expect(writes(f)).toEqual([]);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
it.each([
  'executor',
  'bound',
  'cardinality',
  'first-digest',
  'request-digest',
  'before-start',
  'changed-signature',
  'expired-proof',
  'changed-distribution',
  'issuer-drift',
] as const)('denies %s without admission or permission effects', async (kind) => {
  const f = fixture();
  const a = f.attempts[1]!;
  if (kind === 'executor') f.actor.principalId = f.lease.issuer.workloadPrincipalId;
  if (kind === 'bound') f.step.bound = false;
  if (kind === 'cardinality') f.attempts.pop();
  if (kind === 'first-digest') a.firstDigest = Buffer.alloc(32);
  if (kind === 'request-digest') a.requestDigest = Buffer.alloc(32);
  if (kind === 'before-start') a.startedAtNs = (BigInt(a.observation.recordedAtNs) + 1n).toString();
  if (kind === 'changed-signature') {
    a.observation = { ...a.observation, resultHex: '11'.repeat(64) };
    a.firstObservation = { ...a.observation };
    a.firstDigest = canonicalAuthorizationDigestBytes(a.observation);
    a.digest = a.firstDigest;
  }
  if (kind === 'expired-proof')
    owner.source.mockResolvedValue({
      trust: f.input.oldTrust,
      issuer: f.input.currentIssuer,
      recordedAtNs: BigInt(a.request.challengeExpiresAtNs),
    });
  if (kind === 'changed-distribution')
    owner.distributed.mockResolvedValue({
      descriptor: f.input.descriptor,
      result: { trustDigest: 'sha256:' + '22'.repeat(32) },
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
it.each(['signature', 'event', 'result', 'evidence-digest'] as const)(
  'rejects corrupted historical %s without repeating admission',
  async (kind) => {
    const f = fixture();
    await f.publish();
    f.query.mockClear();
    if (kind === 'signature') f.signer.verifyCanonicalAssertion.mockResolvedValue(false);
    if (kind === 'result')
      f.step.result = {
        ...(f.step.result as object),
        observationsDigest: 'sha256:' + '33'.repeat(32),
      };
    if (kind === 'evidence-digest')
      f.step.digest = createHash('sha256').update('different').digest();
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
it.each(['admission', 'rotation-cas', 'head-cas'] as const)(
  'propagates %s failure to the enclosing transaction without returning completion',
  async (kind) => {
    const f = fixture();
    const original = f.query.getMockImplementation()!;
    f.query.mockImplementation((sql, params) => {
      if (kind === 'admission' && sql.startsWith('select openpc.admit_'))
        throw Error('admission failed');
      if (
        (kind === 'rotation-cas' && sql.startsWith('update control.signing_key_rotation')) ||
        (kind === 'head-cas' && sql.startsWith('update control.outbox_aggregate_head'))
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
