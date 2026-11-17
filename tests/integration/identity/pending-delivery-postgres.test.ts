import { setTimeout as delay } from 'node:timers/promises';

import { Pool, type PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  FullyScopedPendingDeliveryIdentity,
  SafePendingScope,
} from '../../../services/identity-service/src/contracts/pending-delivery.js';
import {
  PendingDeliveryError,
  PendingDeliveryKernel,
  PostgresPendingDeliveryRepository,
} from '../../../services/identity-service/src/domain/pending-delivery-kernel.js';

const runtimeDatabaseUrl = process.env.OPENPC_P00_RUNTIME_DATABASE_URL;
const adminDatabaseUrl = process.env.OPENPC_P00_ADMIN_DATABASE_URL;
const bypassDatabaseUrl = process.env.OPENPC_P00_BYPASS_DATABASE_URL;
const integration =
  runtimeDatabaseUrl === undefined ||
  adminDatabaseUrl === undefined ||
  bypassDatabaseUrl === undefined
    ? describe.skip
    : describe;

const participantUuid = '018f7000-0000-7000-8000-000000000001';
const privacyUuid = '018f7000-0000-7000-8000-000000000002';
const otherParticipantUuid = '018f7000-0000-7000-8000-000000000003';
const otherPrivacyUuid = '018f7000-0000-7000-8000-000000000004';
const leaseOwner = '018f7000-0000-7000-8000-000000000005';
const participantId = `urn:openpc:participant:${participantUuid}`;
const privacyDomainId = `urn:openpc:privacy-domain:${privacyUuid}`;

function bytes(seed: number): Buffer {
  return Buffer.alloc(32, seed);
}

function identity(
  seed: number,
  overrides: Partial<{
    chainId: string;
    profileId: string;
    profileVersion: string;
    protectedDeliveryReferenceDigest: Buffer;
  }> = {},
) {
  return FullyScopedPendingDeliveryIdentity.create({
    participantId,
    privacyDomainId,
    chainId: overrides.chainId ?? String(seed),
    profileId:
      overrides.profileId ??
      `urn:openpc:profile:018f7000-0000-7000-8000-${seed.toString().padStart(12, '0')}`,
    profileVersion: overrides.profileVersion ?? '1.0.0',
    correlatedLogIdentityHmac: bytes(seed),
    entityHmac: bytes(seed + 20),
    entityScopeDigest: bytes(seed + 40),
    deliverySurface: 'HTTP',
    protectedDeliveryReferenceDigest:
      overrides.protectedDeliveryReferenceDigest ?? bytes(seed + 60),
  });
}

async function scoped<T>(
  pool: Pool,
  participant: string,
  privacy: string,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query(
      `select openpc.set_request_context(
         'PARTICIPANT',$1,$2,'018f7000-0000-7000-8000-000000000099',
         'ACT-IDENTITY_UPDATE_PENDING_DELIVERY-V1',true),openpc.assert_request_context(true)`,
      [participant, privacy],
    );
    const result = await operation(client);
    await client.query('commit');
    return result;
  } catch (error) {
    await client.query('rollback').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function rawInsert(
  client: PoolClient,
  seed: number,
  overrides: Partial<{
    chainId: string;
    profileId: string;
    profileVersion: string;
    correlatedLogIdentityHmac: Buffer;
    deliverySurface: string;
    subscriptionReferenceDigest: Buffer | null;
    sessionReferenceDigest: Buffer | null;
    state: string;
  }> = {},
) {
  return client.query(
    `insert into control.pending_delivery
      (participant_id,privacy_domain_id,chain_id,profile_id,profile_version,
       correlated_log_identity_hmac,entity_hmac,entity_scope_digest,delivery_surface,
       protected_delivery_reference_digest,subscription_reference_digest,
       session_reference_digest,state)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [
      participantUuid,
      privacyUuid,
      overrides.chainId ?? String(seed),
      overrides.profileId ??
        `urn:openpc:profile:018f7000-0000-7000-8000-${seed.toString().padStart(12, '0')}`,
      overrides.profileVersion ?? '1.0.0',
      overrides.correlatedLogIdentityHmac ?? bytes(seed),
      bytes(seed + 20),
      bytes(seed + 40),
      overrides.deliverySurface ?? 'HTTP',
      bytes(seed + 60),
      overrides.subscriptionReferenceDigest ?? null,
      overrides.sessionReferenceDigest ?? null,
      overrides.state ?? 'PENDING',
    ],
  );
}

integration('P00 pending-delivery PostgreSQL 18.6 boundary', () => {
  const admin = new Pool({ connectionString: adminDatabaseUrl, max: 2 });
  const runtime = new Pool({ connectionString: runtimeDatabaseUrl, max: 12 });
  const cleanupRuntime = new Pool({ connectionString: runtimeDatabaseUrl, max: 1 });
  const bypass = new Pool({ connectionString: bypassDatabaseUrl, max: 1 });
  const repository = new PostgresPendingDeliveryRepository(runtime, leaseOwner, 2, 20);

  beforeAll(async () => {
    await admin.query(
      `insert into control.participant
         (participant_id,display_name,state,authority_epoch,root_privacy_domain_id)
       values ($1,'P00 local participant','ACTIVE',1,$2)`,
      [participantUuid, privacyUuid],
    );
    await admin.query(
      `insert into control.privacy_domain
         (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
       values ($1,$2,'P00 local privacy','PARTICIPANT_LOCAL','LOCAL_ONLY','ACTIVE')`,
      [privacyUuid, participantUuid],
    );
  });

  afterAll(async () => {
    try {
      await admin.query(`set session_replication_role=replica`);
      await admin.query(`delete from control.pending_delivery where participant_id=$1`, [
        participantUuid,
      ]);
      await admin.query(`delete from control.privacy_domain where participant_id=$1`, [
        participantUuid,
      ]);
      await admin.query(`delete from control.participant where participant_id=$1`, [
        participantUuid,
      ]);
      await admin.query(`set session_replication_role=origin`);
    } finally {
      await Promise.all([runtime.end(), cleanupRuntime.end(), bypass.end(), admin.end()]);
    }
  });

  it('seals exact index, collation, check, trigger, RLS, action, and grant ownership', async () => {
    const catalog = await admin.query<{
      actionCount: number;
      cCollationCount: number;
      checkCount: number;
      forcedRls: boolean;
      indexCount: number;
      nullsNotDistinctCount: number;
      policyCount: number;
      publicPrivilege: boolean;
      runtimeDelete: boolean;
      runtimeForbiddenInsert: boolean;
      runtimeForbiddenUpdate: boolean;
      runtimeInsertColumns: boolean;
      runtimeTableInsert: boolean;
      runtimeTableUpdate: boolean;
      runtimeUpdateColumns: boolean;
      triggerCount: number;
      workerWrite: boolean;
    }>(
      `select
        (select count(*)::int from pg_indexes where schemaname='control'
          and tablename='pending_delivery' and indexname in
          ('pending_delivery_active_full_identity_uq','pending_delivery_full_identity_history_uq',
           'pending_delivery_successor_guard_uq')) "indexCount",
        (select count(*)::int from pg_index i join pg_class c on c.oid=i.indexrelid
          join pg_namespace n on n.oid=c.relnamespace where n.nspname='control'
          and c.relname in ('pending_delivery_active_full_identity_uq',
          'pending_delivery_full_identity_history_uq') and i.indnullsnotdistinct) "nullsNotDistinctCount",
        (select count(*)::int from information_schema.columns where table_schema='control'
          and table_name='pending_delivery' and column_name in ('profile_id','profile_version')
          and collation_name='C') "cCollationCount",
        (select count(*)::int from pg_constraint where conrelid='control.pending_delivery'::regclass
          and contype='c') "checkCount",
        (select relrowsecurity and relforcerowsecurity from pg_class
          where oid='control.pending_delivery'::regclass) "forcedRls",
        (select count(*)::int from pg_policy where polrelid='control.pending_delivery'::regclass
          and polname in ('participant_isolation','privacy_domain_isolation')) "policyCount",
        (select count(*)::int from pg_trigger where tgrelid='control.pending_delivery'::regclass
          and tgname='pending_delivery_lifecycle' and not tgisinternal) "triggerCount",
        (select count(*)::int from control.action_intent where action_intent_id in
          ('ACT-IDENTITY_CREATE_PENDING_DELIVERY-V1',
           'ACT-IDENTITY_UPDATE_PENDING_DELIVERY-V1')) "actionCount",
        has_table_privilege('public','control.pending_delivery','select') "publicPrivilege",
        has_table_privilege('openpc_control_runtime','control.pending_delivery','insert') "runtimeTableInsert",
        has_table_privilege('openpc_control_runtime','control.pending_delivery','update') "runtimeTableUpdate",
        has_column_privilege('openpc_control_runtime','control.pending_delivery','participant_id','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','privacy_domain_id','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','chain_id','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','profile_id','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','profile_version','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','correlated_log_identity_hmac','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','entity_hmac','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','entity_scope_digest','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','delivery_surface','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','protected_delivery_reference_digest','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','subscription_reference_digest','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','session_reference_digest','insert') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','state','insert') "runtimeInsertColumns",
        has_column_privilege('openpc_control_runtime','control.pending_delivery','pending_delivery_id','insert') or
          has_column_privilege('openpc_control_runtime','control.pending_delivery','first_observed_at','insert') or
          has_column_privilege('openpc_control_runtime','control.pending_delivery','lease_owner','insert') "runtimeForbiddenInsert",
        has_column_privilege('openpc_control_runtime','control.pending_delivery','state','update') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','lease_owner','update') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','lease_expires_at','update') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','next_retry_at','update') and
          has_column_privilege('openpc_control_runtime','control.pending_delivery','safe_reason','update') "runtimeUpdateColumns",
        has_column_privilege('openpc_control_runtime','control.pending_delivery','pending_delivery_id','update') or
          has_column_privilege('openpc_control_runtime','control.pending_delivery','participant_id','update') or
          has_column_privilege('openpc_control_runtime','control.pending_delivery','profile_id','update') or
          has_column_privilege('openpc_control_runtime','control.pending_delivery','first_observed_at','update') or
          has_column_privilege('openpc_control_runtime','control.pending_delivery','last_observed_at','update') "runtimeForbiddenUpdate",
        has_table_privilege('openpc_control_runtime','control.pending_delivery','delete') "runtimeDelete",
        has_table_privilege('openpc_control_worker','control.pending_delivery','insert') or
          has_table_privilege('openpc_control_worker','control.pending_delivery','update') or
          has_column_privilege('openpc_control_worker','control.pending_delivery','state','update') "workerWrite"`,
    );
    expect(catalog.rows).toEqual([
      {
        actionCount: 2,
        cCollationCount: 2,
        checkCount: 6,
        forcedRls: true,
        indexCount: 3,
        nullsNotDistinctCount: 2,
        policyCount: 2,
        publicPrivilege: false,
        runtimeDelete: false,
        runtimeForbiddenInsert: false,
        runtimeForbiddenUpdate: false,
        runtimeInsertColumns: true,
        runtimeTableInsert: false,
        runtimeTableUpdate: false,
        runtimeUpdateColumns: true,
        triggerCount: 1,
        workerWrite: false,
      },
    ]);

    const indexes = await admin.query<{ indexdef: string; indexname: string }>(
      `select indexname,indexdef from pg_indexes where schemaname='control'
        and tablename='pending_delivery' order by indexname`,
    );
    const definitions = Object.fromEntries(
      indexes.rows.map(({ indexdef, indexname }) => [indexname, indexdef]),
    );
    const tuple =
      '(participant_id, privacy_domain_id, chain_id, profile_id, profile_version, correlated_log_identity_hmac, entity_hmac, entity_scope_digest, delivery_surface, protected_delivery_reference_digest, subscription_reference_digest, session_reference_digest)';
    expect(definitions.pending_delivery_active_full_identity_uq).toContain(tuple);
    expect(definitions.pending_delivery_active_full_identity_uq).toContain(
      `NULLS NOT DISTINCT WHERE (state = ANY (ARRAY['PENDING'::control.pending_delivery_state, 'LEASED'::control.pending_delivery_state, 'RETRY_WAIT'::control.pending_delivery_state]))`,
    );
    expect(definitions.pending_delivery_full_identity_history_uq).toContain(tuple);
    expect(definitions.pending_delivery_full_identity_history_uq).toContain('NULLS NOT DISTINCT');
    expect(definitions.pending_delivery_successor_guard_uq).toContain(
      '(participant_id, privacy_domain_id, profile_version, protected_delivery_reference_digest)',
    );

    const policies = await admin.query<{ definition: string; name: string }>(
      `select polname name,coalesce(pg_get_expr(polqual,polrelid),'') || ' ' ||
         coalesce(pg_get_expr(polwithcheck,polrelid),'') definition
       from pg_policy where polrelid='control.pending_delivery'::regclass order by polname`,
    );
    expect(policies.rows).toEqual([
      expect.objectContaining({
        name: 'participant_isolation',
        definition: expect.stringContaining('openpc.matches_participant(participant_id)'),
      }),
      expect.objectContaining({
        name: 'privacy_domain_isolation',
        definition: expect.stringContaining('openpc.matches_privacy(privacy_domain_id)'),
      }),
    ]);
  });

  it('AF30-REQ-A28B957731C93D8B08AFAE41 converges concurrent exact enqueue to one row and exact replay receipt', async () => {
    const candidate = identity(1);
    const results = await Promise.all(
      Array.from({ length: 8 }, async () => repository.enqueue(candidate)),
    );
    expect(new Set(results.map((result) => result.pendingDeliveryId))).toHaveLength(1);
    expect(results.filter((result) => !result.replay)).toHaveLength(1);
    expect(results.filter((result) => result.replay)).toHaveLength(7);
    expect(results.every((result) => result.state === 'PENDING')).toBe(true);
    expect(Object.keys(results[0]!)).toEqual(['pendingDeliveryId', 'state', 'replay']);
    const count = await admin.query<{ count: string }>(
      `select count(*)::text from control.pending_delivery
        where participant_id=$1 and protected_delivery_reference_digest=$2`,
      [participantUuid, bytes(61)],
    );
    expect(count.rows).toEqual([{ count: '1' }]);
  });

  it('rejects same guard/different tuple without effect and admits exact successors', async () => {
    const protectedReference = bytes(62);
    const original = identity(2, { protectedDeliveryReferenceDigest: protectedReference });
    await repository.enqueue(original);
    await expect(
      repository.enqueue(
        identity(3, {
          profileVersion: '1.0.0',
          protectedDeliveryReferenceDigest: protectedReference,
        }),
      ),
    ).rejects.toMatchObject({
      code: 'PC-INTEGRATION-5001',
    });
    await expect(
      repository.enqueue(
        identity(4, {
          profileVersion: '2.0.0',
          protectedDeliveryReferenceDigest: protectedReference,
        }),
      ),
    ).resolves.toMatchObject({ replay: false });
    await expect(
      repository.enqueue(identity(5, { protectedDeliveryReferenceDigest: bytes(63) })),
    ).resolves.toMatchObject({ replay: false });
    const count = await admin.query<{ count: string }>(
      `select count(*)::text from control.pending_delivery where participant_id=$1
        and protected_delivery_reference_digest in ($2,$3)`,
      [participantUuid, protectedReference, bytes(63)],
    );
    expect(count.rows).toEqual([{ count: '3' }]);
  });

  it('persists the exact WEBSOCKET and INDEXER conditional reference partitions', async () => {
    const websocketBase = identity(40).snapshot();
    const websocket = FullyScopedPendingDeliveryIdentity.create({
      ...websocketBase,
      deliverySurface: 'WEBSOCKET',
      subscriptionReferenceDigest: bytes(101),
      sessionReferenceDigest: bytes(102),
    });
    const indexerBase = identity(41).snapshot();
    const indexer = FullyScopedPendingDeliveryIdentity.create({
      ...indexerBase,
      deliverySurface: 'INDEXER',
      sessionReferenceDigest: bytes(103),
    });
    await expect(repository.enqueue(websocket)).resolves.toMatchObject({
      replay: false,
      state: 'PENDING',
    });
    await expect(repository.enqueue(indexer)).resolves.toMatchObject({
      replay: false,
      state: 'PENDING',
    });
  });

  it('enforces legal state transitions, terminal history, and stale lease reclaim', async () => {
    const kernel = new PendingDeliveryKernel(repository);
    const delivered = identity(6);
    const created = await repository.enqueue(delivered);
    expect((await kernel.lease(delivered)).state).toBe('LEASED');
    expect((await kernel.deliver(delivered)).state).toBe('DELIVERED');
    await expect(repository.enqueue(delivered)).resolves.toMatchObject({
      pendingDeliveryId: created.pendingDeliveryId,
      replay: true,
      state: 'DELIVERED',
    });
    const terminalCount = await admin.query<{ count: string }>(
      `select count(*)::text from control.pending_delivery where pending_delivery_id=$1`,
      [created.pendingDeliveryId],
    );
    expect(terminalCount.rows).toEqual([{ count: '1' }]);
    await expect(kernel.lease(delivered)).rejects.toMatchObject({
      code: 'PC-INTEGRATION-5001',
    });
    await expect(
      repository.enqueue(
        FullyScopedPendingDeliveryIdentity.create({
          ...delivered.snapshot(),
          protectedDeliveryReferenceDigest: bytes(70),
        }),
      ),
    ).resolves.toMatchObject({ replay: false, state: 'PENDING' });
    await expect(
      repository.enqueue(
        FullyScopedPendingDeliveryIdentity.create({
          ...delivered.snapshot(),
          profileVersion: '2.0.0',
        }),
      ),
    ).resolves.toMatchObject({ replay: false, state: 'PENDING' });

    const retried = identity(7);
    await repository.enqueue(retried);
    await expect(kernel.retry(retried)).rejects.toBeInstanceOf(PendingDeliveryError);
    await kernel.lease(retried);
    await expect(repository.enqueue(retried)).resolves.toMatchObject({
      replay: true,
      state: 'LEASED',
    });
    expect((await kernel.retry(retried)).state).toBe('RETRY_WAIT');
    await expect(repository.enqueue(retried)).resolves.toMatchObject({
      replay: true,
      state: 'RETRY_WAIT',
    });
    expect((await kernel.lease(retried)).state).toBe('LEASED');

    const stale = identity(8);
    await repository.enqueue(stale);
    await kernel.lease(stale);
    await delay(12);
    expect((await kernel.lease(stale)).state).toBe('LEASED');

    const quarantined = identity(9);
    await repository.enqueue(quarantined);
    expect((await kernel.quarantine(quarantined, 'PENDING_SCOPE_INVALID')).state).toBe(
      'QUARANTINED',
    );
  });

  it('rejects field-isolated invalid SQL states, immutable identifiers, and non-lifecycle runtime writes', async () => {
    const candidate = identity(15);
    const created = await repository.enqueue(candidate);
    await expect(
      admin.query(`update control.pending_delivery set chain_id=11 where pending_delivery_id=$1`, [
        created.pendingDeliveryId,
      ]),
    ).rejects.toThrow(/DATA-6020-IMMUTABLE-ROW/u);
    await expect(
      admin.query(
        `update control.pending_delivery
            set pending_delivery_id='018f7000-0000-7000-8000-000000000099'
          where pending_delivery_id=$1`,
        [created.pendingDeliveryId],
      ),
    ).rejects.toThrow(/DATA-6020-IMMUTABLE-ROW/u);
    await expect(
      scoped(runtime, participantUuid, privacyUuid, (client) =>
        client.query(
          `update control.pending_delivery set profile_id=$2 where pending_delivery_id=$1`,
          [created.pendingDeliveryId, identity(16).snapshot().profileId],
        ),
      ),
    ).rejects.toThrow(/permission denied/u);
    const invalidCases = [
      [{ chainId: '18446744073709551616' }, /pending_delivery_chain_id_ck/u],
      [{ profileId: 'not-an-openpc-urn' }, /pending_delivery_profile_id_ck/u],
      [{ profileVersion: '01.0.0' }, /pending_delivery_profile_version_ck/u],
      [{ correlatedLogIdentityHmac: Buffer.alloc(31) }, /pending_delivery_digest_lengths_ck/u],
      [{ deliverySurface: 'EMAIL' }, /invalid input value for enum/u],
      [
        { deliverySurface: 'HTTP', sessionReferenceDigest: bytes(16) },
        /pending_delivery_surface_references_ck/u,
      ],
      [{ deliverySurface: 'WEBSOCKET' }, /pending_delivery_surface_references_ck/u],
      [
        {
          deliverySurface: 'INDEXER',
          subscriptionReferenceDigest: bytes(17),
          sessionReferenceDigest: bytes(18),
        },
        /pending_delivery_surface_references_ck/u,
      ],
      [{ state: 'LEASED' }, /DATA-6021-INCOMPLETE-SECURITY-RECORD/u],
    ] as const;
    for (const [index, [overrides, expected]] of invalidCases.entries()) {
      await expect(
        scoped(runtime, participantUuid, privacyUuid, (client) =>
          rawInsert(client, 30 + index, overrides),
        ),
      ).rejects.toThrow(expected);
    }
  });

  it('rejects superuser and BYPASSRLS repositories and cleans pooled custom GUC state', async () => {
    const superuserRepository = new PostgresPendingDeliveryRepository(admin, leaseOwner);
    const bypassRepository = new PostgresPendingDeliveryRepository(bypass, leaseOwner);
    await expect(superuserRepository.enqueue(identity(70))).rejects.toMatchObject({
      code: 'PC-INTEGRATION-5001',
    });
    await expect(bypassRepository.enqueue(identity(71))).rejects.toMatchObject({
      code: 'PC-INTEGRATION-5001',
    });
    const rejectedRows = await admin.query<{ count: string }>(
      `select count(*)::text from control.pending_delivery where participant_id=$1
        and chain_id in (70,71)`,
      [participantUuid],
    );
    expect(rejectedRows.rows).toEqual([{ count: '0' }]);

    const dirty = await cleanupRuntime.connect();
    await dirty.query(`select set_config('openpc.participant_id',$1,false)`, [
      otherParticipantUuid,
    ]);
    await dirty.query(`select set_config('openpc.context_mode','PARTICIPANT',false)`);
    dirty.release();
    const cleanupRepository = new PostgresPendingDeliveryRepository(cleanupRuntime, leaseOwner);
    await expect(cleanupRepository.enqueue(identity(72))).resolves.toMatchObject({
      replay: false,
      state: 'PENDING',
    });
    const clean = await cleanupRuntime.query<{ clean: boolean }>(
      `select nullif(current_setting('openpc.context_mode',true),'') is null
              and nullif(current_setting('openpc.participant_id',true),'') is null
              and nullif(current_setting('openpc.privacy_domain_id',true),'') is null
              and nullif(current_setting('openpc.operation_id',true),'') is null
              and nullif(current_setting('openpc.action_intent_id',true),'') is null
              and nullif(current_setting('openpc.context_scope',true),'') is null as clean`,
    );
    expect(clean.rows).toEqual([{ clean: true }]);
  });

  it('enforces participant/privacy RLS and computes a one-item safe aggregate', async () => {
    const profileId = 'urn:openpc:profile:018f7000-0000-7000-8000-000000000013';
    await repository.enqueue(identity(13, { profileId }));
    const visible = await repository.summarize(
      SafePendingScope.create({
        participantId,
        privacyDomainId,
        chainId: '13',
        profileId,
        profileVersion: '1.0.0',
        deliverySurface: 'HTTP',
      }),
    );
    expect(visible).toMatchObject({ pendingCount: '1' });
    expect(visible).toHaveProperty('oldestPendingAgeMilliseconds');
    expect(visible).toHaveProperty('asOf');

    const hidden = await scoped(runtime, otherParticipantUuid, otherPrivacyUuid, (client) =>
      client.query<{ count: string }>(
        `select count(*)::text from control.pending_delivery where participant_id=$1`,
        [participantUuid],
      ),
    );
    expect(hidden.rows).toEqual([{ count: '0' }]);
  });

  it('AF30-REQ-05E5C97CD246ED545FB2A3AC returns exact empty/one/many active summaries and oldest age', async () => {
    const profileId = 'urn:openpc:profile:018f7000-0000-7000-8000-000000000020';
    const summaryScope = SafePendingScope.create({
      participantId,
      privacyDomainId,
      chainId: '20',
      profileId,
      profileVersion: '1.0.0',
      deliverySurface: 'HTTP',
    });
    await expect(repository.summarize(summaryScope)).resolves.toMatchObject({
      pendingCount: '0',
      oldestPendingAgeMilliseconds: null,
    });

    const pending = identity(20, { profileId });
    const leased = identity(21, { chainId: '20', profileId });
    const retrying = identity(22, { chainId: '20', profileId });
    const delivered = identity(23, { chainId: '20', profileId });
    const quarantined = identity(24, { chainId: '20', profileId });
    const receipts = await Promise.all(
      [pending, leased, retrying, delivered, quarantined].map(async (candidate) =>
        repository.enqueue(candidate),
      ),
    );
    const kernel = new PendingDeliveryKernel(repository);
    await kernel.lease(leased);
    await kernel.lease(retrying);
    await kernel.retry(retrying);
    await kernel.lease(delivered);
    await kernel.deliver(delivered);
    await kernel.quarantine(quarantined, 'PENDING_SCOPE_INVALID');

    const adminClient = await admin.connect();
    let oldest: Date;
    try {
      await adminClient.query('begin');
      await adminClient.query(`set local session_replication_role=replica`);
      const anchorResult = await adminClient.query<{ anchor: Date }>(
        `select date_trunc('milliseconds',clock_timestamp()) anchor`,
      );
      const anchor = anchorResult.rows[0]!.anchor;
      oldest = new Date(anchor.getTime() - 9_000);
      await adminClient.query(
        `update control.pending_delivery set
           first_observed_at=case pending_delivery_id
             when $1 then $4::timestamptz-interval '9 seconds'
             when $2 then $4::timestamptz-interval '5 seconds'
             else $4::timestamptz-interval '1 second'
           end,
           last_observed_at=$4::timestamptz
         where pending_delivery_id=any($3::uuid[])`,
        [
          receipts[0]!.pendingDeliveryId,
          receipts[1]!.pendingDeliveryId,
          receipts.slice(0, 3).map((receipt) => receipt.pendingDeliveryId),
          anchor,
        ],
      );
      await adminClient.query('commit');
    } catch (error) {
      await adminClient.query('rollback');
      throw error;
    } finally {
      adminClient.release();
    }

    const summary = (await repository.summarize(summaryScope)) as {
      pendingCount: string;
      oldestPendingAgeMilliseconds: string | null;
      asOf: string;
    };
    expect(summary.pendingCount).toBe('3');
    expect(summary.oldestPendingAgeMilliseconds).toBe(
      String(Date.parse(summary.asOf) - oldest.getTime()),
    );
  });

  it('keeps kernel summaries authorization-first over the live repository', async () => {
    const localScope = SafePendingScope.create({
      participantId,
      privacyDomainId,
      chainId: '99',
      profileId: 'urn:openpc:profile:018f7000-0000-7000-8000-000000000099',
      profileVersion: '1.0.0',
      deliverySurface: 'HTTP',
    });
    const authorityContext = {
      principalId: `urn:openpc:principal:${participantUuid}`,
      participantId,
      privacyDomainId,
      sessionId: `urn:openpc:session:${participantUuid}`,
      authorityEnvelopeId: `urn:openpc:authority-envelope:${participantUuid}`,
      authorityEpoch: '1',
      delegationEpoch: '1',
      actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' as const,
      policyGenerationDigest: `sha256:${'a'.repeat(64)}` as const,
      factGenerationDigest: `sha256:${'b'.repeat(64)}` as const,
    };
    const kernel = new PendingDeliveryKernel(repository, {
      async evaluate(request) {
        return {
          decision: 'ALLOW',
          authorized: true,
          terminal: false,
          existenceVisible: true,
          payloadVisible: true,
          authorityContext: request.authorityContext,
          inputsDigest: request.inputsDigest,
          evaluatedAt: '2026-09-05T00:00:00.000000Z',
          explanationCodes: ['AUTHORITY_ALLOW'],
          traceSetId: 'TS-ID-AUTHORIZATION',
        };
      },
    });
    await expect(kernel.summary(localScope, authorityContext)).resolves.toEqual({
      pendingCount: '0',
      oldestPendingAgeMilliseconds: null,
      asOf: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/u),
    });
  });
});
