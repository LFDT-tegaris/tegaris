import type { Pool } from 'pg';
import { beforeEach, expect, it, vi } from 'vitest';
import { readPlatformScopeReadiness } from '../../../identity-service/src/db/platform-scope-commit-store.js';
import { fenceBoundAuthorities } from '../../../identity-service/src/db/authority-fence.js';
import { assertPlatformBootstrapActor } from '../../../identity-service/src/domain/bootstrap-authority.js';
import { PostgresParticipantRepository, type AuthenticatedActor } from './participant-kernel.js';

it('resolves authority in the target privacy scope and cannot borrow pooled or foreign scope', async () => {
  let privacy: unknown = privacyDomainId;
  let operation: unknown;
  const grant = {
    participant_id: participantId,
    principal_id: principalId,
    authority_envelope_id: '018f0000-0000-7000-8000-000000000601',
    assignment_id: '018f0000-0000-7000-8000-000000000801',
    role_id: null,
    privacy_domain_ids: [privacyDomainId],
    action_intent_ids: [actionIntentId],
    resource_ids: [roleId],
    risk_classes: ['LOW'],
    maker_checker_required: true,
    step_up_required: true,
    onward_delegation_depth: 0,
    authority_epoch: '1',
    delegation_epoch: '1',
    state: 'ACTIVE',
    valid_from: new Date('2026-01-01T00:00:00Z'),
    valid_until: new Date('2027-01-01T00:00:00Z'),
    semantic_digest: Buffer.alloc(32, 1),
    scope_digest: Buffer.alloc(32, 2),
  };
  const query = vi.fn(async (sql: string, values?: unknown[]) => {
    if (sql === 'discard all') privacy = null;
    if (sql.includes(' as clean')) return { rowCount: 1, rows: [{ clean: true }] };
    if (sql.includes('openpc.set_request_context')) {
      privacy = values?.[1];
      operation = values?.[2];
    }
    if (sql.includes('r.rolbypassrls'))
      return {
        rowCount: 1,
        rows: [
          {
            participant_id: participantId,
            privacy_domain_id: privacy,
            operation_id: operation,
            action_intent_id: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
            bypass: false,
            superuser: false,
          },
        ],
      };
    if (sql.includes('with recursive targets')) {
      const permitted = privacy === privacyDomainId && values?.[2] === privacyDomainId;
      return {
        rowCount: permitted ? 1 : 0,
        rows: permitted ? [{ assignment_id: grant.assignment_id, delegation_path: [] }] : [],
      };
    }
    if (
      sql.includes('from control.assignment') ||
      sql.includes('select e.* from control.authority_envelope')
    )
      return { rowCount: 1, rows: [grant] };
    if (sql.includes('from control.participant') || sql.includes('from control.principal'))
      return { rowCount: 1, rows: [{ authority_epoch: '1' }] };
    return { rowCount: 0, rows: [] };
  });
  const release = vi.fn();
  const pool = { connect: vi.fn(async () => ({ query, release })) } as unknown as Pool;
  const repository = new PostgresParticipantRepository(pool);
  const target = { privacyDomainId, resourceId: roleId, actionIntentId, riskClass: 'LOW' };
  const admitted = await repository.effectiveAuthority(actor(true), participantId, target);
  expect(admitted?.envelope.id).toBe(grant.authority_envelope_id);
  expect(admitted?.assignment.id).toBe(grant.assignment_id);
  expect(privacy).toBeNull();
  query.mockClear();
  await expect(
    repository.effectiveAuthority(actor(true), participantId, {
      ...target,
      privacyDomainId: '018f0000-0000-7000-8000-000000000202',
    }),
  ).resolves.toBeUndefined();
  expect(
    query.mock.calls.some(([sql]) => sql.includes('select e.* from control.authority_envelope')),
  ).toBe(false);
  expect(privacy).toBeNull();
  expect(release).toHaveBeenCalledTimes(2);
});

vi.mock('../../../identity-service/src/db/authority-fence.js', async (original) => ({
  ...(await original<Record<string, unknown>>()),
  fenceBoundAuthorities: vi.fn(async () => ({})),
}));
vi.mock('../../../identity-service/src/domain/bootstrap-authority.js', async (original) => ({
  ...(await original<Record<string, unknown>>()),
  assertPlatformBootstrapActor: vi.fn(async () => undefined),
}));
vi.mock('../../../identity-service/src/db/platform-scope-commit-store.js', async (original) => ({
  ...(await original<Record<string, unknown>>()),
  readPlatformScopeReadiness: vi.fn(),
}));
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const roleId = '018f0000-0000-7000-8000-000000000501';
const principalId = '018f0000-0000-7000-8000-000000000111';
const sessionId = '018f0000-0000-7000-8000-000000000701';
const actionIntentId = 'ACT-PARTICIPANTS_READ_RESOURCE-V1';
function actor(platform: boolean): AuthenticatedActor {
  return {
    participantId,
    principalId,
    sessionId,
    platform,
    boundParticipantEpoch: '1',
    boundPrincipalEpoch: '1',
    boundEnvelopeEpoch: '1',
    readAuthorization: {
      participantEpoch: '1',
      principalEpoch: '1',
      authorityEpoch: '1',
      principalId,
      sessionId,
      sessionEpoch: '1',
      privacyDomainId,
      actionIntentId,
      resourceId: roleId,
      assignmentId: '018f0000-0000-7000-8000-000000000801',
      assignmentRowVersion: '1',
      authorityEnvelopeId: '018f0000-0000-7000-8000-000000000601',
      delegationEpoch: '1',
    },
  };
}
function database(platformSession: boolean) {
  let operationId: string;
  const query = vi.fn(async (sql: string, values?: unknown[]) => {
    if (sql.includes(' as clean')) return { rowCount: 1, rows: [{ clean: true }] };
    if (sql.includes('openpc.set_request_context')) operationId = String(values?.[2]);
    if (sql.includes('r.rolbypassrls'))
      return {
        rowCount: 1,
        rows: [
          {
            participant_id: participantId,
            privacy_domain_id: privacyDomainId,
            operation_id: operationId,
            action_intent_id: actionIntentId,
            bypass: false,
            superuser: false,
          },
        ],
      };
    if (sql.startsWith('with permissions')) {
      const permitted = !platformSession || values?.[6] === true;
      return { rowCount: permitted ? 1 : 0, rows: permitted ? [{ session_id: sessionId }] : [] };
    }
    if (sql.includes('from control.authority_role role'))
      return {
        rowCount: 1,
        rows: [
          {
            role: {
              roleId: `urn:openpc:role:${roleId}`,
              version: '1',
              actions: [actionIntentId],
              origin: 'BOOTSTRAP',
              createdByPrincipalId: principalId,
              creatorParticipantId: participantId,
              bootstrapMandateId: null,
              bootstrapPlatformParticipantId: participantId,
            },
          },
        ],
      };
    return { rowCount: 0, rows: [] };
  });
  const release = vi.fn();
  const pool = { connect: vi.fn(async () => ({ query, release })) } as unknown as Pool;
  return { repository: new PostgresParticipantRepository(pool), query, release };
}
beforeEach(() => vi.clearAllMocks());
it.each([true, false])(
  'keeps role read custody and the explicit session mode fence (Platform=%s)',
  async (platform) => {
    const db = database(platform);
    const reader = actor(platform);
    const result = await db.repository.getRoleBindingPreview(
      reader,
      participantId,
      privacyDomainId,
      roleId,
    );
    expect(result).toMatchObject({ participantId, roleId, revision: '1' });
    expect(fenceBoundAuthorities).toHaveBeenCalledWith(expect.anything(), participantId, [
      reader.readAuthorization,
    ]);
    expect(assertPlatformBootstrapActor).toHaveBeenCalledTimes(platform ? 1 : 0);
    if (platform)
      expect(assertPlatformBootstrapActor).toHaveBeenCalledWith(
        expect.anything(),
        participantId,
        principalId,
        sessionId,
      );
    const assurance = db.query.mock.calls.find(([sql]) => sql.startsWith('with permissions'));
    expect(assurance?.[1]?.[6]).toBe(platform);
    expect(assurance?.[0]).toContain(
      'openpc.session_step_up_valid_until(session.participant_id,session.session_id,session.principal_id)>clock_timestamp()',
    );
    expect(db.query).toHaveBeenCalledWith('commit');
    expect(db.release).toHaveBeenCalledOnce();
  },
);
it('does not turn a Participant read into a Platform session exception', async () => {
  const db = database(true);
  await expect(
    db.repository.getRoleBindingPreview(actor(false), participantId, privacyDomainId, roleId),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
  expect(assertPlatformBootstrapActor).not.toHaveBeenCalled();
  expect(
    db.query.mock.calls.some(([sql]) => sql.includes('from control.authority_role role')),
  ).toBe(false);
  expect(db.query).toHaveBeenCalledWith('rollback');
});
it('rejects a stale bound epoch before reading the role and rolls back', async () => {
  const db = database(true);
  const current = actor(true);
  const reader = {
    ...current,
    readAuthorization: { ...current.readAuthorization!, authorityEpoch: '2' },
  };
  await expect(
    db.repository.getRoleBindingPreview(reader, participantId, privacyDomainId, roleId),
  ).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
  expect(fenceBoundAuthorities).not.toHaveBeenCalled();
  expect(
    db.query.mock.calls.some(([sql]) => sql.includes('from control.authority_role role')),
  ).toBe(false);
  expect(db.query).toHaveBeenCalledWith('rollback');
});

it.each(['declared', 'foreign', 'committed', 'expired'] as const)(
  'fences Participant readiness before returning a declared handoff: %s',
  async (mode) => {
    const db = database(false);
    const reader = actor(false);
    const readiness = {
      state: mode === 'committed' ? 'COMMITTED' : 'WITHDRAWING',
      sourceExpiresAtNs: mode === 'expired' ? '10' : '20',
      nowNs: '10',
      administrators: [{ principalId: mode === 'foreign' ? roleId : principalId }],
    } as Awaited<ReturnType<typeof readPlatformScopeReadiness>>;
    vi.mocked(readPlatformScopeReadiness).mockResolvedValue(readiness);
    const operation = db.repository.platformScopeReadiness(reader, privacyDomainId, roleId);
    if (mode === 'declared') {
      await expect(operation).resolves.toBe(readiness);
      expect(db.query).toHaveBeenCalledWith('commit');
    } else {
      await expect(operation).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
      expect(db.query).toHaveBeenCalledWith('rollback');
    }
    expect(fenceBoundAuthorities).toHaveBeenCalledWith(expect.anything(), participantId, [
      reader.readAuthorization,
    ]);
    expect(assertPlatformBootstrapActor).not.toHaveBeenCalled();
    expect(db.query.mock.calls.find(([sql]) => sql.startsWith('with permissions'))?.[1]?.[6]).toBe(
      false,
    );
  },
);
