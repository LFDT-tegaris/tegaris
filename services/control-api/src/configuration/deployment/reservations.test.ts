import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Pool, type PoolClient } from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { localOperationId as id } from '../../../../identity-service/src/domain/local-operation-id.js';
import {
  expireUnhandedDeploymentAddress,
  handoffDeploymentAddress,
  parseDeploymentReservationBinding,
  reserveDeploymentAddress,
  type DeploymentReservationBinding,
} from './reservations.js';

const digest = () => `sha256:${randomBytes(32).toString('hex')}`;
const hash = () => `0x${randomBytes(32).toString('hex')}`;
const address = () => `0x${randomBytes(20).toString('hex')}`;
function binding(
  overrides: Partial<DeploymentReservationBinding> = {},
): DeploymentReservationBinding {
  return {
    attemptId: id(),
    commandId: id(),
    participantId: id(),
    privacyDomainId: id(),
    targetRuntimeId: 'target:first',
    chainId: '1',
    genesisDigest: digest(),
    contractAddress: address(),
    senderAddress: address(),
    creatorAddress: address(),
    mechanism: 'CREATE2',
    saltNamespaceDigest: digest(),
    effectiveSalt: hash(),
    artifactDigest: digest(),
    initCodeHash: hash(),
    intentDigest: digest(),
    profileDigest: digest(),
    generationDigest: digest(),
    transactionHash: hash(),
    preparedRecordDigest: digest(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    ...overrides,
  };
}

it('rejects noncanonical chain/address/attempt/salt identities and caller-added state', () => {
  const valid = binding();
  expect(parseDeploymentReservationBinding(valid)).toEqual(valid);
  for (const change of [
    { chainId: '01' },
    { chainId: '0x1' },
    { chainId: 'invalid' },
    { chainId: '0' },
    { chainId: (2n ** 256n).toString() },
    { chainId: '1'.repeat(1000) },
    { contractAddress: valid.contractAddress!.toUpperCase() },
    { attemptId: 'caller' },
    { effectiveSalt: null },
    { saltNamespaceDigest: null },
    { mechanism: 'CREATE' },
    { mechanism: 'TRANSACTION_CREATE', effectiveSalt: null, saltNamespaceDigest: null },
    { state: 'HANDOFF' },
    { nativeValueAuthorizationId: id() },
    { nativeValueAuthorizationDigest: digest() },
    { expiresAt: 'infinity' },
    { targetRuntimeId: 'x' },
    { mechanism: 'CREATE3' },
    { helperAddress: address() },
    { mechanism: 'CREATE3', helperAddress: valid.contractAddress },
  ])
    expect(() => parseDeploymentReservationBinding({ ...valid, ...change })).toThrow(
      'INVALID_BINDING',
    );
  expect(
    parseDeploymentReservationBinding({
      ...valid,
      mechanism: 'TRANSACTION_CREATE',
      creatorAddress: valid.senderAddress,
      effectiveSalt: null,
      saltNamespaceDigest: null,
    }).mechanism,
  ).toBe('TRANSACTION_CREATE');
});

const databaseUrl = process.env.OPENPC_DEPLOYMENT_RESERVATION_DATABASE_URL;
const apiDatabaseUrl = process.env.OPENPC_DEPLOYMENT_API_DATABASE_URL;
if (process.env.OPENPC_REQUIRE_DEPLOYMENT_RESERVATIONS === '1' && (!databaseUrl || !apiDatabaseUrl))
  throw new Error('deployment reservation database prerequisite missing');

// DEPLOY-PROFILE-CONTRACT-003: deterministic-address coordination.
// Real least-privilege PostgreSQL custody component. No public intent/profile,
// policy, approval, target dispatch or provider state is fabricated as acceptance.
describe.skipIf(!databaseUrl)('durable deployment address coordination', () => {
  const pool = new Pool({ connectionString: databaseUrl, max: 4 });
  const apiPool = apiDatabaseUrl
    ? new Pool({ connectionString: apiDatabaseUrl, max: 1 })
    : undefined;
  afterAll(async () => {
    await pool.end();
    await apiPool?.end();
  });

  async function scoped<T>(
    claim: DeploymentReservationBinding,
    run: (client: PoolClient) => Promise<T>,
    selectedPool = pool,
  ): Promise<T> {
    const client = await selectedPool.connect();
    try {
      await client.query('begin');
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-DEPLOYMENT_RESERVATION_TEST-V1',true)`,
        [claim.participantId, claim.privacyDomainId, claim.commandId],
      );
      const result = await run(client);
      await client.query('commit');
      return result;
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  }
  const reserve = (claim: DeploymentReservationBinding) =>
    scoped(claim, (client) => reserveDeploymentAddress(client, claim, '9'));
  const handoff = (claim: DeploymentReservationBinding) =>
    scoped(claim, (client) => handoffDeploymentAddress(client, claim));
  const expire = (claim: DeploymentReservationBinding) =>
    scoped(claim, (client) => expireUnhandedDeploymentAddress(client, claim));

  it.skipIf(!apiPool)(
    'reads predecessor custody through the API role without worker mutation rights',
    async () => {
      const claim = binding();
      await scoped(
        claim,
        async (client) => {
          const rights = await client.query<{ readable: boolean; mutable: boolean }>(
            "select has_table_privilege(current_user,'control.deployment_address_reservation','SELECT') readable, has_table_privilege(current_user,'control.deployment_address_reservation','UPDATE') mutable",
          );
          expect(rights.rows).toEqual([{ readable: true, mutable: false }]);
          const result = await client.query(
            readFileSync(new URL('./predecessor-source.sql', import.meta.url), 'utf8'),
            [claim.participantId, claim.privacyDomainId, id(), claim.commandId],
          );
          expect(result.rows).toEqual([]);
        },
        apiPool!,
      );
    },
  );

  it('holds both CREATE3 addresses against every cross-scope address role without exposing claims', async () => {
    const first = binding({ mechanism: 'CREATE3', helperAddress: address() });
    const saved = await reserve(first);
    expect((await reserve(first)).binding).toEqual(saved.binding);
    const keys = await scoped(first, (client) =>
      client.query<{ address: string; active: boolean }>(
        'select address,active from control.deployment_address_claim where attempt_id=$1 order by address',
        [first.attemptId],
      ),
    );
    expect(keys.rows).toEqual(
      [first.contractAddress!, first.helperAddress!]
        .sort()
        .map((address) => ({ address, active: true })),
    );
    for (const occupied of [first.contractAddress!, first.helperAddress!]) {
      for (const helper of [false, true]) {
        const other = binding({
          chainId: first.chainId,
          genesisDigest: first.genesisDigest,
          ...(helper
            ? { mechanism: 'CREATE3', helperAddress: occupied }
            : { contractAddress: occupied }),
        });
        await expect(reserve(other)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
        expect(
          (
            await scoped(other, (client) =>
              client.query(
                'select address from control.deployment_address_claim where attempt_id=$1',
                [first.attemptId],
              ),
            )
          ).rowCount,
        ).toBe(0);
      }
    }
    for (const statement of [
      'update control.deployment_address_claim set active=false where attempt_id=$1',
      'delete from control.deployment_address_claim where attempt_id=$1',
    ])
      await expect(
        scoped(first, (client) => client.query(statement, [first.attemptId])),
      ).rejects.toThrow();
    await handoff(first);
    await expect(expire(first)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(
      (
        await scoped(first, (client) =>
          client.query(
            'select address from control.deployment_address_claim where attempt_id=$1 and active',
            [first.attemptId],
          ),
        )
      ).rowCount,
    ).toBe(2);
  });

  it('serializes intersecting CREATE3 pairs and releases both only on governed pre-handoff expiry', async () => {
    const first = binding({
      mechanism: 'CREATE3',
      helperAddress: address(),
      expiresAt: new Date(Date.now() + 700).toISOString(),
    });
    const second = binding({
      mechanism: 'CREATE3',
      helperAddress: first.contractAddress!,
      contractAddress: first.helperAddress!,
      chainId: first.chainId,
      genesisDigest: first.genesisDigest,
      expiresAt: first.expiresAt,
    });
    const results = await Promise.allSettled([reserve(first), reserve(second)]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const winner = results[0]!.status === 'fulfilled' ? first : second;
    await afterExpiry(winner);
    expect((await expire(winner)).state).toBe('EXPIRED');
    expect(
      (
        await scoped(winner, (client) =>
          client.query(
            'select address from control.deployment_address_claim where attempt_id=$1 and not active',
            [winner.attemptId],
          ),
        )
      ).rowCount,
    ).toBe(2);
    const successor = binding({
      mechanism: 'CREATE3',
      helperAddress: winner.contractAddress!,
      contractAddress: winner.helperAddress!,
      chainId: winner.chainId,
      genesisDigest: winner.genesisDigest,
    });
    expect((await reserve(successor)).state).toBe('RESERVED');
    expect((await reserve(winner)).state).toBe('EXPIRED');
  });

  it('preserves upgraded held nonces and quarantines unresolved legacy custody across tenant scopes', async () => {
    // Seeded predecessor rows come from the migration runner, never business acceptance.
    for (const marker of ['7', '8']) {
      const claim = binding({
        chainId: '31337',
        genesisDigest: `sha256:${'7'.repeat(64)}`,
        senderAddress: `0x${marker.repeat(40)}`,
        mechanism: 'CREATE',
        contractAddress: null,
        saltNamespaceDigest: null,
        effectiveSalt: null,
      });
      await expect(reserve(claim)).rejects.toThrow(marker === '7' ? 'UNAVAILABLE' : 'PC-DATA-6004');
      expect(
        await scoped(
          claim,
          async (client) =>
            (
              await client.query(
                'select attempt_id from control.deployment_address_reservation where sender_address=$1',
                [claim.senderAddress],
              )
            ).rows,
        ),
      ).toEqual([]);
    }
  });
  async function afterExpiry(claim: DeploymentReservationBinding) {
    await pool.query(
      `select pg_sleep(greatest(0,extract(epoch from $1::timestamptz-clock_timestamp()))+0.01)`,
      [claim.expiresAt],
    );
  }

  it('holds symbolic factory CREATE sender nonces across targets and distinct transaction hashes', async () => {
    const first = binding({
      mechanism: 'CREATE',
      contractAddress: null,
      effectiveSalt: null,
      saltNamespaceDigest: null,
    });
    const second = binding({
      ...first,
      attemptId: id(),
      commandId: id(),
      participantId: id(),
      privacyDomainId: id(),
      targetRuntimeId: 'target:second',
      transactionHash: hash(),
      creatorAddress: address(),
    });
    const results = await Promise.allSettled([reserve(first), reserve(second)]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(
      results.filter((result) => result.status === 'rejected').map((result) => result.reason.code),
    ).toEqual(['UNAVAILABLE']);
    const winner = results[0]!.status === 'fulfilled' ? first : second;
    await expect(
      scoped(winner, (client) => reserveDeploymentAddress(client, winner, '10')),
    ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    const distinctNonce = binding({
      ...winner,
      attemptId: id(),
      commandId: id(),
      transactionHash: hash(),
    });
    expect(
      (
        await scoped(distinctNonce, (client) =>
          reserveDeploymentAddress(client, distinctNonce, '10'),
        )
      ).binding.contractAddress,
    ).toBeNull();
    expect((await handoff(winner)).transitioned).toBe(true);
    const direct = binding({
      ...winner,
      attemptId: id(),
      commandId: id(),
      transactionHash: hash(),
      mechanism: 'TRANSACTION_CREATE',
      contractAddress: address(),
      creatorAddress: winner.senderAddress,
    });
    await expect(reserve(direct)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    for (const nonce of ['-1', '01', '0x9', (2n ** 64n).toString()])
      await expect(
        scoped(winner, (client) => reserveDeploymentAddress(client, winner, nonce)),
      ).rejects.toMatchObject({ code: 'INVALID_BINDING' });
  });

  it('serializes competing targets and preserves the exact winner across connections', async () => {
    expect(
      (await pool.query('select rolsuper,rolbypassrls from pg_roles where rolname=current_user'))
        .rows,
    ).toEqual([{ rolsuper: false, rolbypassrls: false }]);
    const first = binding();
    const second = binding({
      ...first,
      attemptId: id(),
      commandId: id(),
      participantId: id(),
      privacyDomainId: id(),
      transactionHash: hash(),
      targetRuntimeId: 'target:second',
    });
    const results = await Promise.allSettled([reserve(first), reserve(second)]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(
      results
        .filter((result) => result.status === 'rejected')
        .map((result) => result.reason.message),
    ).toEqual(['UNAVAILABLE']);
    const winner = results[0]!.status === 'fulfilled' ? first : second;
    const reopened = new Pool({ connectionString: databaseUrl, max: 1 });
    try {
      expect(
        (await scoped(winner, (client) => reserveDeploymentAddress(client, winner, '9'), reopened))
          .binding,
      ).toEqual(winner);
    } finally {
      await reopened.end();
    }
    const handoffs = await Promise.all([handoff(winner), handoff(winner)]);
    expect(handoffs.map((result) => result.transitioned).sort()).toEqual([false, true]);
  });

  it('converges concurrent exact reserve retries on one immutable claim', async () => {
    const first = binding();
    const results = await Promise.all([reserve(first), reserve(first), reserve(first)]);
    expect(results[1]).toEqual(results[0]);
    expect(results[2]).toEqual(results[0]);
    expect(results[0]?.state).toBe('RESERVED');
  });

  it('conflicts across Participants/privacy domains without exposing the other claim', async () => {
    const first = binding();
    await reserve(first);
    for (const scope of [
      { participantId: id(), privacyDomainId: id() },
      { privacyDomainId: id() },
    ]) {
      const other = binding({
        ...first,
        ...scope,
        attemptId: id(),
        commandId: id(),
        transactionHash: hash(),
        creatorAddress: address(),
        saltNamespaceDigest: digest(),
        targetRuntimeId: 'target:other',
      });
      await expect(reserve(other)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
      expect(
        await scoped(
          other,
          async (client) =>
            (
              await client.query(
                'select attempt_id from control.deployment_address_reservation where chain_id=$1 and genesis_digest=$2 and contract_address=$3',
                [first.chainId, first.genesisDigest, first.contractAddress],
              )
            ).rows,
        ),
      ).toEqual([]);
    }
    // A genuinely different genesis is a distinct physical chain, unlike a local network alias.
    await expect(
      reserve(binding({ ...first, attemptId: id(), commandId: id(), genesisDigest: digest() })),
    ).resolves.toMatchObject({ state: 'RESERVED' });
  });

  it('preserves immutable identity on replay and prevents cross-mechanism/address aliases', async () => {
    const first = binding();
    const original = await reserve(first);
    expect(await reserve(first)).toEqual(original);
    for (const change of [
      { targetRuntimeId: 'target:second' },
      { generationDigest: digest() },
      { preparedRecordDigest: digest() },
      { transactionHash: hash() },
      { profileDigest: digest() },
      { expiresAt: new Date(Date.now() + 120_000).toISOString() },
    ]) {
      await expect(reserve({ ...first, ...change })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
      await expect(handoff({ ...first, ...change })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    }
    await expect(
      reserve(
        binding({
          ...first,
          attemptId: id(),
          commandId: id(),
          transactionHash: hash(),
          mechanism: 'CREATE',
          saltNamespaceDigest: null,
          effectiveSalt: null,
        }),
      ),
    ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    await expect(
      reserve(binding({ ...first, attemptId: id(), commandId: id(), contractAddress: address() })),
    ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(await reserve(first)).toEqual(original);
  });

  it('expires only before handoff and never renews or retries the old attempt/bytes', async () => {
    const first = binding({ expiresAt: new Date(Date.now() + 300).toISOString() });
    await reserve(first);
    await expect(expire(first)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    await afterExpiry(first);
    await expect(handoff(first)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect((await expire(first)).state).toBe('EXPIRED');
    expect((await reserve(first)).state).toBe('EXPIRED');
    expect((await handoff(first)).transitioned).toBe(false);
    await expect(
      reserve(
        binding({
          ...first,
          attemptId: id(),
          commandId: id(),
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        }),
      ),
    ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    const next = binding({
      ...first,
      attemptId: id(),
      commandId: id(),
      transactionHash: hash(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    expect((await reserve(next)).state).toBe('RESERVED');
    expect((await handoff(next)).transitioned).toBe(true);
  });

  it('retains a lost handoff acknowledgement after expiry and database reconnect', async () => {
    const first = binding({ expiresAt: new Date(Date.now() + 300).toISOString() });
    await reserve(first);
    // Commit succeeded; discard its acknowledgement before a target can confirm start.
    await handoff(first);
    await afterExpiry(first);
    const reopened = new Pool({ connectionString: databaseUrl, max: 1 });
    try {
      const result = await scoped(
        first,
        (client) => handoffDeploymentAddress(client, first),
        reopened,
      );
      expect(result.transitioned).toBe(false);
      expect(result.reservation.state).toBe('HANDOFF');
      expect(result.reservation.handoffAt).not.toBeNull();
    } finally {
      await reopened.end();
    }
    await expect(expire(first)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    await expect(
      reserve(
        binding({
          ...first,
          attemptId: id(),
          commandId: id(),
          transactionHash: hash(),
          targetRuntimeId: 'target:replacement',
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        }),
      ),
    ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
  });

  it('does not let a waiter hand off an expired reservation using its transaction start time', async () => {
    const first = binding({ expiresAt: new Date(Date.now() + 300).toISOString() });
    await reserve(first);
    let waiting: Promise<unknown> | undefined;
    let signalStarted: () => void = () => undefined;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    await scoped(first, async (client) => {
      await client.query(
        'select attempt_id from control.deployment_address_reservation where attempt_id=$1 for update',
        [first.attemptId],
      );
      waiting = scoped(first, (waiter) => {
        signalStarted();
        return handoffDeploymentAddress(waiter, first);
      }).catch((error: unknown) => error);
      await started;
      await afterExpiry(first);
      await expireUnhandedDeploymentAddress(client, first);
    });
    expect(await waiting).toMatchObject({ transitioned: false, reservation: { state: 'EXPIRED' } });
  });

  it('enforces immutable custody and least-privilege writes even when the repository is bypassed', async () => {
    const first = binding();
    await reserve(first);
    for (const statement of [
      "update control.deployment_address_reservation set target_runtime_id='target:stolen' where attempt_id=$1",
      "update control.deployment_address_reservation set expires_at=expires_at+interval '1 hour' where attempt_id=$1",
      "update control.deployment_address_reservation set state='EXPIRED' where attempt_id=$1",
      'delete from control.deployment_address_reservation where attempt_id=$1',
    ])
      await expect(
        scoped(first, (client) => client.query(statement, [first.attemptId])),
      ).rejects.toThrow();
    await handoff(first);
    for (const statement of [
      "update control.deployment_address_reservation set state='RESERVED',handoff_at=null where attempt_id=$1",
      "update control.deployment_address_reservation set state='EXPIRED',handoff_at=null where attempt_id=$1",
    ])
      await expect(
        scoped(first, (client) => client.query(statement, [first.attemptId])),
      ).rejects.toThrow('PC-DATA-6004');
    const runtimeUrl = new URL(databaseUrl!);
    runtimeUrl.username = 'openpc_configuration_runtime';
    const runtime = new Pool({ connectionString: runtimeUrl.href, max: 1 });
    try {
      expect(
        (await scoped(first, (client) => reserveDeploymentAddress(client, first, '9'), runtime))
          .state,
      ).toBe('HANDOFF');
      await expect(
        scoped(
          first,
          (client) =>
            client.query(
              "update control.deployment_address_reservation set state='EXPIRED' where attempt_id=$1",
              [first.attemptId],
            ),
          runtime,
        ),
      ).rejects.toMatchObject({ code: '42501' });
      const next = binding();
      await expect(
        scoped(next, (client) => reserveDeploymentAddress(client, next, '9'), runtime),
      ).rejects.toMatchObject({ code: '42501' });
    } finally {
      await runtime.end();
    }
  });
  it('rejects a forged predecessor reference without the exact governed successor candidate', async () => {
    const original = binding();
    await reserve(original);
    await handoff(original);
    for (const predecessor of [original.commandId, id()]) {
      await expect(
        scoped(original, (client) =>
          client.query(
            `insert into control.deployment_address_reservation
         select (jsonb_populate_record(null::control.deployment_address_reservation,
           to_jsonb(original)||$2::jsonb)).*
         from control.deployment_address_reservation original where original.attempt_id=$1`,
            [
              original.attemptId,
              JSON.stringify({
                attempt_id: id(),
                command_id: id(),
                predecessor_command_id: predecessor,
                transaction_hash: hash(),
                state: 'RESERVED',
                handoff_at: null,
              }),
            ],
          ),
        ),
      ).rejects.toThrow('PC-DATA-6004');
    }
    await expect(
      scoped(original, (client) =>
        client.query(
          'update control.deployment_address_reservation set predecessor_command_id=$2 where attempt_id=$1',
          [original.attemptId, id()],
        ),
      ),
    ).rejects.toThrow('PC-DATA-6004');
    expect((await handoff(original)).reservation.state).toBe('HANDOFF');
    expect(
      (
        await scoped(original, (client) =>
          client.query(
            'select count(*)::integer n from control.deployment_address_reservation where predecessor_command_id=$1',
            [original.commandId],
          ),
        )
      ).rows[0]?.n,
    ).toBe(0);
  });
});
