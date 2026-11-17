import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  administrationReservationSchema,
  createAdministrationReservationSchema,
  type AdministrationReservation,
  type ReservationBinding,
} from '../administration-resource-reservation-contract.js';
import { canonicalJson } from '../domain/digest.js';
import {
  assertReservationBinding,
  consumeAdministrationReservation,
  readAdministrationReservation,
} from './administration-resource-reservation.js';
import { reserveAdministrationResourceName } from './administration-resource-reservation-store.js';
import type { PublicApprovalScope } from './public-approval-store.js';

vi.mock('../../../identity-service/src/db/authority-fence.js', () => ({
  fenceBoundAuthorities: vi.fn(),
  AuthorityFenceError: class extends Error {},
}));

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const hash = (value: unknown) => createHash('sha256').update(canonicalJson(value)).digest();
const now = new Date('2026-10-01T15:00:00.000Z');
const binding: ReservationBinding = {
  purpose: 'APPROVAL_REQUEST',
  businessActionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  businessResourceId: id(401),
  expectedBusinessRevision: '1',
  checkerPrincipalId: id(112),
};
const scope: PublicApprovalScope = {
  participantId: id(101),
  privacyDomainId: id(201),
  principalId: id(111),
  operationId: id(501),
  actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'a'.repeat(64)}`,
  idempotencyKey: 'reserve-administration-01',
  authority: {
    privacyDomainId: id(201),
    principalId: id(111),
    sessionId: id(701),
    sessionEpoch: '1',
    participantEpoch: '1',
    principalEpoch: '1',
    assignmentId: id(801),
    assignmentRowVersion: '1',
    authorityEnvelopeId: id(901),
    authorityEpoch: '1',
    delegationEpoch: '1',
    actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    resourceId: id(111),
  },
};
function reservation(): AdministrationReservation {
  return administrationReservationSchema.parse({
    ...binding,
    kind: 'ADMINISTRATION_RESOURCE_NAME',
    version: 1,
    operationId: id(501),
    reservedResourceId: id(601),
    participantId: id(101),
    privacyDomainId: id(201),
    makerPrincipalId: id(111),
    createdAt: now.toISOString(),
    validUntil: new Date(now.getTime() + 3_600_000).toISOString(),
    authorityEffect: 'NONE',
    requiresFreshAuthority: true,
  });
}

function consumptionClient(payload: unknown = reservation(), used = false) {
  const query = vi.fn(async (sql: string) => {
    if (sql.includes('from control.idempotency_record'))
      return {
        rowCount: 1,
        rows: [
          {
            payload,
            resultDigest: hash(payload),
            actionIntentId: scope.actionIntentId,
            now,
          },
        ],
      };
    if (sql.includes('pg_try_advisory_xact_lock')) return { rowCount: 1, rows: [{ held: true }] };
    if (sql.startsWith('select exists(')) return { rowCount: 1, rows: [{ used }] };
    throw new Error('Unexpected database operation');
  });
  return { client: { query } as unknown as PoolClient, query };
}

describe('finite administration name reservations', () => {
  it('consumes a matching name without granting authority or creating intermediate business state', async () => {
    const { client, query } = consumptionClient();
    await expect(consumeAdministrationReservation(client, scope, id(501), binding)).resolves.toBe(
      id(601),
    );
    expect(query.mock.calls).toHaveLength(3);
    expect(query.mock.calls.every(([sql]) => sql.trimStart().startsWith('select '))).toBe(true);
  });
  it.each(['participantId', 'privacyDomainId', 'principalId'] as const)(
    'rejects a different %s',
    (field) => {
      expect(() =>
        assertReservationBinding(reservation(), { ...scope, [field]: id(999) }, binding, now),
      ).toThrow('PC-POLICY-2003');
    },
  );
  it.each([
    { purpose: 'POLICY_ACTIVATION_OCCURRENCE' as const },
    { businessResourceId: id(402) },
    { businessActionIntentId: 'ACT-PARTICIPANTS_CREATE_RESOURCE-V1' },
    { expectedBusinessRevision: '2' },
    { checkerPrincipalId: id(113) },
  ])('rejects rebinding %j', (change) => {
    expect(() =>
      assertReservationBinding(reservation(), scope, { ...binding, ...change }, now),
    ).toThrow('PC-POLICY-2003');
  });
  it('rejects expiry at the exact boundary and any extension beyond one hour', () => {
    expect(() =>
      assertReservationBinding(reservation(), scope, binding, new Date(reservation().validUntil)),
    ).toThrow('PC-POLICY-2003');
    expect(() =>
      assertReservationBinding(
        { ...reservation(), validUntil: '2026-10-01T16:00:00.001Z' },
        scope,
        binding,
        now,
      ),
    ).toThrow('PC-POLICY-2003');
  });
  it('rejects a used name, rather than rebinding or replaying the effect', async () => {
    const { client } = consumptionClient(reservation(), true);
    await expect(consumeAdministrationReservation(client, scope, id(501), binding)).rejects.toThrow(
      'PC-POLICY-2002',
    );
  });
  it('rejects a fabricated authority-bearing result and a mismatched ledger operation', async () => {
    await expect(
      readAdministrationReservation(
        consumptionClient({ ...reservation(), authorityEffect: 'ALLOW' }).client,
        scope,
        id(501),
      ),
    ).rejects.toThrow('PC-POLICY-2001');
    await expect(
      readAdministrationReservation(consumptionClient().client, scope, id(502)),
    ).rejects.toThrow('PC-POLICY-2001');
  });
  it('strictly binds reservation purpose to the existing creation action', () => {
    const body = {
      ...binding,
      command: 'RESERVE_RESOURCE_NAME',
      makerSubjectRef: `urn:openpc:resource:${id(111)}`,
      actionIntentId: scope.actionIntentId,
      actionIntentDigest: scope.actionIntentDigest,
    };
    expect(createAdministrationReservationSchema.safeParse(body).success).toBe(true);
    expect(
      createAdministrationReservationSchema.safeParse({
        ...body,
        purpose: 'POLICY_ACTIVATION_OCCURRENCE',
      }).success,
    ).toBe(false);
    expect(
      createAdministrationReservationSchema.safeParse({ ...body, signedProof: 'untrusted' })
        .success,
    ).toBe(false);
  });
});

function creationFixture(
  options: {
    deadline?: Date;
    failReadback?: boolean;
    selfApproval?: boolean;
    replay?: boolean;
    renewal?: boolean;
    used?: boolean;
    successor?: boolean;
    wrongOwner?: boolean;
    live?: boolean;
    missingExactAuthority?: boolean;
    contended?: boolean;
  } = {},
) {
  let stored: AdministrationReservation | undefined = options.replay ? reservation() : undefined;
  const predecessor = {
    ...reservation(),
    operationId: id(500),
    createdAt: new Date(now.getTime() - 3_600_000).toISOString(),
    validUntil: new Date(now.getTime() + (options.live ? 1000 : 0)).toISOString(),
    ...(options.wrongOwner ? { makerPrincipalId: id(999) } : {}),
  };
  const statements: string[] = [];
  const query = vi.fn(async (sql: string, args: readonly unknown[] = []) => {
    statements.push(sql);
    if (/^(begin|set local|select openpc.set_request_context|commit|rollback)/u.test(sql))
      return { rowCount: 1, rows: [] };
    if (sql.includes('from control.action_intent'))
      return {
        rowCount: 1,
        rows: sql.includes('operation_class')
          ? [
              {
                operationClass: 'CREATE',
                resourceType: 'approval-requests',
                semanticDigest: Buffer.from('a'.repeat(64), 'hex'),
              },
            ]
          : [{}],
      };
    if (sql.startsWith('insert into control.idempotency_record'))
      return { rowCount: options.replay ? 0 : 1, rows: [{}] };
    if (sql.includes('input_digest as "inputDigest"'))
      return {
        rowCount: 1,
        rows: [
          {
            inputDigest: hash(binding),
            expectedRevision: '0',
            terminalState: 'COMMITTED',
            resultPayload: stored,
          },
        ],
      };
    if (
      sql.startsWith('with recursive authority_chain') &&
      args[3] === id(601) &&
      options.missingExactAuthority
    )
      return { rowCount: 0, rows: [] };
    if (sql.includes('pg_try_advisory_xact_lock'))
      return { rowCount: 1, rows: [{ held: !options.contended }] };
    if (sql.startsWith('select exists('))
      return {
        rowCount: 1,
        rows: [
          sql.includes('predecessorOperationId')
            ? { present: !!options.successor }
            : { used: !!options.used },
        ],
      };
    if (sql.startsWith('with recursive authority_chain'))
      return {
        rowCount: 1,
        rows: [
          {
            assignmentId: id(801),
            authorityEnvelopeId: id(901),
            sessionAbsoluteExpiresAt: new Date('2026-10-01T18:00:00.000Z'),
            sessionIdleExpiresAt: new Date('2026-10-01T17:00:00.000Z'),
            authorityValidUntil: options.deadline ?? null,
          },
        ],
      };
    if (sql === 'select clock_timestamp() as now') return { rowCount: 1, rows: [{ now }] };
    if (sql.includes('from control.principal')) return { rowCount: 1, rows: [{}] };
    if (sql.startsWith('update control.idempotency_record')) {
      stored = args[3] as AdministrationReservation;
      return { rowCount: 1, rows: [] };
    }
    if (sql.includes('from control.idempotency_record')) {
      if (options.failReadback) throw new Error('readback unavailable');
      const payload = options.renewal && args[3] === id(500) ? predecessor : stored;
      return {
        rowCount: 1,
        rows: [
          {
            payload,
            resultDigest: hash(payload),
            actionIntentId: scope.actionIntentId,
            now,
          },
        ],
      };
    }
    throw new Error('Unexpected database operation');
  });
  const release = vi.fn();
  const pool = { connect: vi.fn(async () => ({ query, release })) } as unknown as Pool;
  return {
    pool,
    statements,
    release,
    binding: options.selfApproval ? { ...binding, checkerPrincipalId: scope.principalId } : binding,
  };
}

describe('durable reservation owner', () => {
  it('commits only the name ledger and verifies exact durable readback', async () => {
    const f = creationFixture();
    const result = await reserveAdministrationResourceName(f.pool, scope, f.binding, f.binding);
    expect(result.validUntil).toBe('2026-10-01T16:00:00.000Z');
    expect(result.authorityEffect).toBe('NONE');
    expect(
      f.statements
        .filter((sql) => /^(insert|update)/u.test(sql))
        .every((sql) => sql.includes('control.idempotency_record')),
    ).toBe(true);
    expect(f.statements.at(-1)).toBe('commit');
    expect(f.release).toHaveBeenCalledOnce();
  });
  it('renews only an expired unused exact name under current authority and preserves its predecessor', async () => {
    const f = creationFixture({ renewal: true });
    const result = await reserveAdministrationResourceName(
      f.pool,
      scope,
      binding,
      { ...binding, predecessorOperationId: id(500) },
      id(500),
    );
    expect(result).toMatchObject({
      ...binding,
      reservedResourceId: id(601),
      predecessorOperationId: id(500),
      operationId: id(501),
      createdAt: now.toISOString(),
      authorityEffect: 'NONE',
    });
    expect(f.statements.filter((sql) => sql.startsWith('update '))).toHaveLength(1);
    expect(f.statements.at(-1)).toBe('commit');
  });
  it.each([
    { used: true },
    { successor: true },
    { wrongOwner: true },
    { live: true },
    { missingExactAuthority: true },
    { contended: true },
  ])('denies an invalid name successor without a durable result: %j', async (options) => {
    const f = creationFixture({ renewal: true, ...options });
    await expect(
      reserveAdministrationResourceName(f.pool, scope, binding, binding, id(500)),
    ).rejects.toThrow();
    expect(f.statements.at(-1)).toBe('rollback');
    expect(f.statements.some((sql) => sql.startsWith('update '))).toBe(false);
  });
  it('bounds a name by the shorter live grant', async () => {
    const f = creationFixture({ deadline: new Date('2026-10-01T15:02:00.000Z') });
    expect(
      (await reserveAdministrationResourceName(f.pool, scope, binding, binding)).validUntil,
    ).toBe('2026-10-01T15:02:00.000Z');
  });
  it('returns the original exact name on replay and does not allocate or rewrite it', async () => {
    const f = creationFixture({ replay: true });
    await expect(
      reserveAdministrationResourceName(f.pool, scope, binding, binding),
    ).resolves.toEqual(reservation());
    expect(f.statements.some((sql) => sql.startsWith('update '))).toBe(false);
    expect(f.statements.find((sql) => sql.includes('input_digest as "inputDigest"'))).toContain(
      'privacy_domain_id=$5',
    );
  });
  it('rejects a replay with changed intent and rolls back its transaction', async () => {
    const f = creationFixture({ replay: true });
    const changed = { ...binding, expectedBusinessRevision: '2' };
    await expect(
      reserveAdministrationResourceName(f.pool, scope, changed, changed),
    ).rejects.toThrow('PC-POLICY-2002');
    expect(f.statements.at(-1)).toBe('rollback');
  });
  it.each([{ deadline: now }, { selfApproval: true }, { failReadback: true }])(
    'rolls back failed admission or readback: %j',
    async (options) => {
      const f = creationFixture(options);
      await expect(
        reserveAdministrationResourceName(f.pool, scope, f.binding, f.binding),
      ).rejects.toThrow();
      expect(f.statements).toContain('rollback');
      expect(f.statements).not.toContain('commit');
      expect(f.release).toHaveBeenCalledOnce();
    },
  );
});
