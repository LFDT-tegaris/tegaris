import { generateKeyPairSync } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import { canonicalAuthorizationDigestBytes } from '../../identity-service/src/contracts/authorization.js';
import {
  identityEnvelopeRotationRequestSchema,
  identityEnvelopeRotationRequestDigest,
  type IdentityEnvelopeRotationObservation,
} from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';
import { PostgresIdentityEnvelopeRotationAttemptStore } from './identity-envelope-rotation-store.js';

const tx = vi.hoisted(() => ({ query: vi.fn(), events: [] as string[], scopes: [] as unknown[] }));
vi.mock('../../identity-service/src/db/scoped-transaction.js', () => ({
  runScopedTransaction: async (
    _pool: unknown,
    scope: unknown,
    operationId: () => string,
    operation: (client: { query: typeof tx.query }) => Promise<unknown>,
  ) => {
    tx.scopes.push(scope);
    tx.events.push('begin:' + operationId());
    try {
      const value = await operation({ query: tx.query });
      tx.events.push('commit');
      return value;
    } catch (error) {
      tx.events.push('rollback');
      throw error;
    }
  },
}));
beforeEach(() => {
  vi.resetAllMocks();
  tx.events.length = 0;
  tx.scopes.length = 0;
});
const id = (n: number) => `01990000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
function fixture(state = 'READY') {
  const request = identityEnvelopeRotationRequestSchema.parse({
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'local',
    workloadCredentialId: id(3),
    workloadCredentialEpoch: '1',
    secretClass: 'SECRET-SIGNING-KEY',
    reference: 'secret://local/envelope#2',
    version: '2',
    purpose: identityEnvelopeContext.purpose,
    purposeCode: 371,
    schemaId: 24034,
    schemaVersion: 1,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
    callerWorkloadCredentialId: id(3),
    rotationId: id(4),
    operationId: id(5),
    attemptId: id(6),
    issuerParticipantEpoch: '7',
    issuerPrincipalEpoch: '2',
    governanceDigest: 'sha256:' + '71'.repeat(32),
    method: 'PREPARE',
  });
  const publicKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  const binding = {
    participantId: request.participantId,
    privacyDomainId: request.privacyDomainId,
    environmentId: request.environmentId,
    workloadCredentialId: request.workloadCredentialId,
    workloadCredentialEpoch: request.workloadCredentialEpoch,
    secretClass: request.secretClass,
    reference: request.reference,
    version: request.version,
    purpose: request.purpose,
    purposeCode: request.purposeCode,
    schemaId: request.schemaId,
    schemaVersion: request.schemaVersion,
    schemaDefinitionDigest: request.schemaDefinitionDigest,
    profileId: request.profileId,
    profileVersion: request.profileVersion,
    profileDigest: request.profileDigest,
  };
  const observation: IdentityEnvelopeRotationObservation = {
    schemaVersion: 1,
    providerId: 'local-provider',
    attemptId: request.attemptId,
    operationId: request.operationId,
    requestDigest: identityEnvelopeRotationRequestDigest(request),
    method: 'PREPARE',
    recordedAtNs: '100000',
    outcome: 'SUCCEEDED',
    reason: null,
    resultHex: null,
    descriptor: {
      ...binding,
      algorithm: 'ES256',
      publicKeySpkiHex: publicKey.toString('hex'),
      fingerprint: evidenceKeyId(publicKey),
      validFromNs: '1000',
      validUntilNs: '900000',
      state: 'ACTIVE',
      revokedAtNs: null,
      retiredAtNs: null,
    },
  };
  const row = {
    request,
    requestDigest: Buffer.from(identityEnvelopeRotationRequestDigest(request).slice(7), 'hex'),
    state,
    stepState: state === 'READY' ? 'READY' : 'STARTED',
    enrollmentId: id(9),
    first: null as IdentityEnvelopeRotationObservation | null,
    observation: null as IdentityEnvelopeRotationObservation | null,
    workloadKeyDigest: 'sha256:' + '81'.repeat(32),
  };
  tx.query.mockImplementation(async (sql: string, values: unknown[]) => {
    if (sql.startsWith('select a.attempt_id'))
      return {
        rowCount: 1,
        rows: [
          { attemptId: request.attemptId, operationId: request.operationId, enrollmentId: id(9) },
        ],
      };
    if (sql.startsWith('select a.request')) {
      tx.events.push(sql.includes('for update') ? 'attempt-lock' : 'discover-attempt');
      return { rowCount: 1, rows: [{ ...row }] };
    }
    if (sql.startsWith('select * from openpc.lock_')) {
      tx.events.push('source-lock');
      return { rowCount: 1, rows: [{}] };
    }
    if (sql.startsWith('select operation_id')) {
      tx.events.push('step-lock');
      return { rowCount: 1, rows: [{}] };
    }
    if (sql.startsWith('update control.identity_envelope_rotation_step')) {
      tx.events.push('step-update');
      row.stepState = sql.includes("state='WRITE_AMBIGUITY'") ? 'WRITE_AMBIGUITY' : 'STARTED';
      return { rowCount: 1, rows: [] };
    }
    if (sql.startsWith('update control.identity_envelope_rotation_attempt')) {
      tx.events.push('attempt-update');
      if (sql.includes("state='STARTED'")) row.state = 'STARTED';
      if (sql.includes('first_observation=$3'))
        row.first = values[2] as IdentityEnvelopeRotationObservation;
      if (sql.includes("state='OBSERVED'")) {
        row.state = 'OBSERVED';
        row.observation = values[2] as IdentityEnvelopeRotationObservation;
      }
      if (sql.includes("set state='WRITE_AMBIGUITY'")) row.state = 'WRITE_AMBIGUITY';
      return { rowCount: 1, rows: [] };
    }
    throw Error('unexpected query');
  });
  const scope = {
    participantId: request.participantId,
    privacyDomainId: request.privacyDomainId,
    environmentId: request.environmentId,
    callerWorkloadCredentialId: request.callerWorkloadCredentialId,
    callerWorkloadKeyDigest: row.workloadKeyDigest,
  };
  return {
    request,
    observation,
    row,
    scope,
    store: new PostgresIdentityEnvelopeRotationAttemptStore({} as never, scope),
  };
}
it('returns PERFORM only after exact source/parent/attempt locks and committed STARTED changes', async () => {
  const f = fixture();
  expect(await f.store.claimNext()).toEqual({ request: f.request, mode: 'PERFORM' });
  expect(tx.events.indexOf('source-lock')).toBeLessThan(tx.events.indexOf('step-lock'));
  expect(tx.events.indexOf('step-lock')).toBeLessThan(tx.events.indexOf('attempt-lock'));
  expect(tx.events.indexOf('step-update')).toBeLessThan(tx.events.indexOf('attempt-update'));
  expect(tx.events.at(-1)).toBe('commit');
  expect(tx.events).toContain('begin:' + f.request.operationId);
  expect(
    tx.scopes.every(
      (s) =>
        JSON.stringify(s) ===
        JSON.stringify({
          participantId: f.scope.participantId,
          privacyDomainId: f.scope.privacyDomainId,
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        }),
    ),
  ).toBe(true);
});

it.each(['READY', 'STARTED'])(
  'rejects a transport key different from the immutable lease before %s dispatch',
  async (state) => {
    const f = fixture(state);
    f.row.workloadKeyDigest = 'sha256:' + '82'.repeat(32);
    await expect(f.store.claimNext()).rejects.toThrow('persistence unavailable');
    expect(tx.events).not.toContain('step-update');
    expect(tx.events).not.toContain('attempt-update');
    expect(tx.events.at(-1)).toBe('rollback');
  },
);
it.each(['STARTED', 'WRITE_AMBIGUITY'])(
  'only looks up an existing %s attempt without new starts',
  async (state) => {
    const f = fixture(state);
    f.row.first = f.observation;
    expect(await f.store.claimNext()).toEqual({
      request: f.request,
      mode: 'LOOKUP',
      firstObservation: f.observation,
    });
    expect(tx.events).not.toContain('source-lock');
    expect(tx.events).not.toContain('attempt-update');
    expect(tx.events).not.toContain('step-update');
  },
);
it('persists first then matching original confirmation, with parent locks first and idempotent resolved readback', async () => {
  const f = fixture('STARTED');
  await f.store.recordFirst(f.request, f.observation);
  expect(tx.events.indexOf('step-lock')).toBeLessThan(tx.events.indexOf('attempt-lock'));
  expect(tx.query.mock.calls.find(([sql]) => sql.includes('first_observation=$3'))![1][3]).toEqual(
    canonicalAuthorizationDigestBytes(f.observation),
  );
  await f.store.recordResolved(f.request, f.observation);
  const effects = tx.events.filter((e) => e === 'attempt-update').length;
  await f.store.recordFirst(f.request, f.observation);
  await f.store.recordResolved(f.request, f.observation);
  expect(tx.events.filter((e) => e === 'attempt-update')).toHaveLength(effects);
});
it('preserves a typed first failure and closes the step without changing immutable request or first response', async () => {
  const f = fixture('STARTED');
  f.row.first = f.observation;
  await f.store.recordAmbiguous(f.request, 'NOT_FOUND');
  const mutation = tx.query.mock.calls.find(([sql]) => sql.includes('ambiguity_kind=coalesce'))!;
  expect(mutation[1][2]).toBe('NOT_FOUND');
  expect(mutation[0]).not.toMatch(/\b(request|first_observation)\s*=/u);
  expect(f.row.first).toEqual(f.observation);
  expect(f.row.stepState).toBe('WRITE_AMBIGUITY');
});
it.each(['changed-first', 'unconfirmed', 'changed-request', 'wrong-scope', 'wrong-digest'])(
  'rejects %s without observed publication',
  async (failure) => {
    const f = fixture('STARTED');
    if (failure === 'changed-first') f.row.first = { ...f.observation, recordedAtNs: '101000' };
    if (failure === 'changed-request')
      Object.assign(f.request, { reference: 'secret://local/foreign#2' });
    if (failure === 'wrong-scope') f.scope.callerWorkloadCredentialId = id(99);
    if (failure === 'wrong-digest') f.row.requestDigest = Buffer.alloc(32, 1);
    await expect(f.store.recordResolved(f.request, f.observation)).rejects.toThrow();
    expect(tx.query.mock.calls.some(([sql]) => sql.startsWith('update'))).toBe(false);
  },
);
it('does not release PERFORM when the exact READY claim is rejected', async () => {
  const f = fixture();
  const original = tx.query.getMockImplementation()!;
  tx.query.mockImplementation(async (sql: string, values: unknown[]) =>
    sql.startsWith('update control.identity_envelope_rotation_attempt')
      ? { rowCount: 0, rows: [] }
      : original(sql, values),
  );
  await expect(f.store.claimNext()).rejects.toThrow();
  expect(tx.events.at(-1)).toBe('rollback');
});
