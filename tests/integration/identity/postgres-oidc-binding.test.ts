import { localOperationId as randomUUID } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildIdentityService } from '../../../services/identity-service/src/app.js';
import { createHttpOidcTrustAdapter } from '../../../services/identity-service/src/domain/http-oidc-trust-adapter.js';
import { oidcProviderFixture } from './oidc-provider-fixture.js';
import { setTimeout as delay } from 'node:timers/promises';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

async function assertSessionHeartbeatSerializableSnapshot(runtime: Pool, token: string) {
  const repository = new PostgresIdentityRepository(runtime);
  const before = await repository.sessionSnapshot(token);
  const reader = await runtime.connect();
  async function begin() {
    await reader.query('begin isolation level serializable');
    await reader.query(
      `select openpc.set_request_context('PARTICIPANT',$1,null,$2,
        'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',false),openpc.assert_request_context(false)`,
      [before.participantId, randomUUID()],
    );
    return (
      await reader.query<{ xmin: string }>(
        'select xmin::text from control.session where participant_id=$1 and session_id=$2',
        [before.participantId, before.sessionId],
      )
    ).rows[0]!.xmin;
  }
  async function lockSession() {
    return reader.query<{ xmin: string }>(
      'select xmin::text from control.session where participant_id=$1 and session_id=$2 for share',
      [before.participantId, before.sessionId],
    );
  }
  try {
    await begin();
    const due = new PostgresIdentityRepository(runtime, {
      now: () => new Date(before.lastSeenAt.getTime() + 2_000),
    });
    const refreshed = await due.sessionSnapshot(token);
    await expect(lockSession()).rejects.toMatchObject({ code: '40001' });
    await reader.query('rollback');

    const originalXmin = await begin();
    const burst = new PostgresIdentityRepository(runtime, {
      now: () => new Date(refreshed.lastSeenAt.getTime() + 1),
    });
    const stored = await burst.sessionSnapshot(token);
    expect(stored.lastSeenAt).toEqual(refreshed.lastSeenAt);
    expect(stored.idleExpiresAt).toEqual(refreshed.idleExpiresAt);
    expect((await lockSession()).rows[0]!.xmin).toBe(originalXmin);
    await reader.query('commit');
  } finally {
    await reader.query('rollback');
    reader.release();
  }
}

async function assertSessionHeartbeatLockOrder(
  admin: Pool,
  repository: PostgresIdentityRepository,
  token: string,
) {
  const before = await repository.sessionSnapshot(token);
  const blocker = await admin.connect();
  let pending: Promise<unknown> | undefined;
  try {
    await blocker.query('begin');
    await blocker.query("set local lock_timeout='300ms'");
    const {
      rows: [{ pid }],
    } = await blocker.query<{ pid: number }>('select pg_backend_pid() pid');
    await blocker.query(
      'select participant_id from control.participant where participant_id=$1 for update',
      [before.participantId],
    );
    const outcome = repository.sessionSnapshot(token).then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    pending = outcome;
    let waiting = false;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const blocked = await admin.query<{ waiting: boolean }>(
        `select exists(select 1 from pg_stat_activity
          where $1=any(pg_blocking_pids(pid)) and query like '%control.participant%') waiting`,
        [pid],
      );
      if (blocked.rows[0]?.waiting) {
        waiting = true;
        break;
      }
      await delay(10);
    }
    expect(waiting, 'heartbeat must physically wait on the Participant root').toBe(true);
    // An authority transaction can lock the session while it owns the root.
    // The old session-first heartbeat held this row and inverted that order.
    await blocker.query(
      'select session_id from control.session where participant_id=$1 and session_id=$2 for share',
      [before.participantId, before.sessionId],
    );
    await blocker.query('rollback');
    const result = await outcome;
    if ('error' in result) throw result.error;
    expect(result.value).toMatchObject({
      participantId: before.participantId,
      principalId: before.principalId,
      sessionId: before.sessionId,
      state: 'ACTIVE',
      absoluteExpiresAt: before.absoluteExpiresAt,
    });
    expect(result.value.idleExpiresAt.getTime()).toBeGreaterThanOrEqual(
      before.idleExpiresAt.getTime(),
    );
  } finally {
    await blocker.query('rollback');
    blocker.release();
    await pending;
  }
}

integration(
  'resolves standard signed OIDC identity only in the server-selected Participant after restart',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const runtime = new Pool({ connectionString: runtimeUrl });
    const participantId = randomUUID(),
      otherParticipantId = randomUUID();
    const principalId = randomUUID(),
      otherPrincipalId = randomUUID();
    const provider = await oidcProviderFixture(participantId, principalId, 'verified-account', {
      membershipHints: false,
    });
    const configuration = {
      issuer: provider.issuer,
      clientId: provider.clientId,
      redirectUri: provider.redirectUri,
    };
    const trust = createHttpOidcTrustAdapter(
      { verifyWebAuthnAssertion: async () => undefined },
      { allowInsecureHttp: true },
    );
    const repository = new PostgresIdentityRepository(runtime);
    const createApp = () =>
      buildIdentityService(
        new IdentityKernel(new PostgresIdentityRepository(runtime)),
        trust,
        configuration,
      );
    let app = createApp();
    try {
      // Initial trust only: two separate memberships deliberately share an external account.
      // This proves scoped admission, not global identity linking or invitation acceptance.
      for (const [pid, principal] of [
        [participantId, principalId],
        [otherParticipantId, otherPrincipalId],
      ]) {
        await admin.query(
          `insert into control.participant(participant_id,display_name,state,authority_epoch) values ($1,'Selected OIDC fixture','ACTIVE',1)`,
          [pid],
        );
        await admin.query(
          `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values ($1,$2,'USER','OIDC fixture','ACTIVE',1)`,
          [principal, pid],
        );
        await admin.query(
          `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from) values ($1,$2,'OIDC_SUBJECT',$3,'verified-account',$4,'ACTIVE',1,clock_timestamp()-interval '1 minute')`,
          [pid, principal, provider.issuer, provider.clientId],
        );
      }
      async function begin(selected?: string, wrongNonce = false) {
        const response = await app.inject({
          method: 'POST',
          url: '/api/v1/session/oidc/authorization',
          payload: selected ? { participantId: selected } : {},
        });
        expect(response.statusCode, response.body).toBe(200);
        const started = response.json();
        const cookie = String(response.headers['set-cookie']).split(';')[0]!;
        const authorization = new URL(`${provider.issuer}/authorize`);
        authorization.search = new URLSearchParams({
          response_type: 'code',
          scope: 'openid',
          client_id: started.clientId,
          redirect_uri: started.redirectUri,
          state: started.state,
          nonce: wrongNonce ? `${started.nonce}-wrong` : started.nonce,
          code_challenge: started.codeChallenge,
          code_challenge_method: 'S256',
        }).toString();
        const grant = await fetch(authorization, { redirect: 'manual' });
        expect(grant.status).toBe(302);
        const callback = new URL(grant.headers.get('location')!);
        return {
          started,
          cookie,
          payload: {
            transactionId: started.transactionId,
            state: callback.searchParams.get('state')!,
            authorizationCode: callback.searchParams.get('code')!,
          },
        };
      }
      const selected = await begin(participantId);
      await app.close();
      app = createApp();
      const missingCustody = await app.inject({
        method: 'POST',
        url: '/api/v1/session/oidc/callback',
        payload: selected.payload,
      });
      expect(missingCustody.statusCode).toBe(401);
      const crossSelection = await app.inject({
        method: 'POST',
        url: '/api/v1/session/oidc/callback',
        headers: { cookie: selected.cookie },
        payload: { ...selected.payload, participantId: otherParticipantId },
      });
      expect(crossSelection.statusCode).toBe(401);
      const responses = await Promise.all(
        [1, 2].map(() =>
          app.inject({
            method: 'POST',
            url: '/api/v1/session/oidc/callback',
            headers: { cookie: selected.cookie },
            payload: selected.payload,
          }),
        ),
      );
      expect(responses.map((response) => response.statusCode).sort()).toEqual([201, 401]);
      const accepted = responses.find((response) => response.statusCode === 201)!;
      const token = /__Host-openpc_session=([^;]+)/u.exec(
        String(accepted.headers['set-cookie']),
      )![1]!;
      expect(await repository.sessionSnapshot(token)).toMatchObject({
        participantId,
        principalId,
        contextMode: 'PLATFORM',
        state: 'ACTIVE',
      });
      const authentication = await admin.query(
        `select occurrence_id,privacy_domain_id,method,source_id,session_id,receipt,receipt_digest
         from control.authentication_occurrence where participant_id=$1`,
        [participantId],
      );
      expect(authentication.rowCount).toBe(1);
      expect(authentication.rows[0]).toMatchObject({
        privacy_domain_id: null,
        method: 'OIDC_CODE_PKCE_S256',
        source_id: selected.payload.transactionId,
      });
      const occurrence = JSON.parse(authentication.rows[0].receipt.toString('utf8'));
      expect(occurrence).toMatchObject({
        version: 'OPENPC_AUTHENTICATION_OCCURRENCE_V1',
        participantId,
        principalId,
        privacyDomainId: null,
        contextMode: 'PLATFORM',
        authorityEffect: 'NONE',
        integrity: 'CONTROL_DATABASE_IMMUTABLE',
      });
      for (const forbidden of ['verified-account', selected.payload.authorizationCode, token])
        expect(authentication.rows[0].receipt.toString('utf8')).not.toContain(forbidden);
      expect(occurrence).not.toHaveProperty('sessionId');
      expect(occurrence.sessionBindingDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(authentication.rows[0].receipt.toString('utf8')).not.toContain(token.split('.')[1]);
      await expect(
        admin.query(
          'update control.authentication_occurrence set receipt=receipt where occurrence_id=$1',
          [authentication.rows[0].occurrence_id],
        ),
      ).rejects.toThrow();
      await assertSessionHeartbeatSerializableSnapshot(runtime, token);
      await assertSessionHeartbeatLockOrder(admin, repository, token);
      await expect(
        repository.sessionSnapshot(`${randomUUID()}.${randomUUID()}`),
      ).rejects.toMatchObject({
        code: 'PC-AUTH-0003',
      });
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.session where participant_id=$1`,
            [participantId],
          )
        ).rows[0].count,
      ).toBe(1);
      for (const pending of [
        await begin(undefined),
        await begin(participantId, true),
        await begin(randomUUID()),
      ]) {
        const rejected = await app.inject({
          method: 'POST',
          url: '/api/v1/session/oidc/callback',
          headers: { cookie: pending.cookie },
          payload: pending.payload,
        });
        expect(rejected.statusCode, rejected.body).toBe(401);
      }
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.authentication_occurrence where participant_id=$1',
            [participantId],
          )
        ).rows[0].count,
      ).toBe(1);
      const other = await begin(otherParticipantId);
      const second = await app.inject({
        method: 'POST',
        url: '/api/v1/session/oidc/callback',
        headers: { cookie: other.cookie },
        payload: other.payload,
      });
      expect(second.statusCode, second.body).toBe(201);
      const secondToken = /__Host-openpc_session=([^;]+)/u.exec(
        String(second.headers['set-cookie']),
      )![1]!;
      expect(await repository.sessionSnapshot(secondToken)).toMatchObject({
        participantId: otherParticipantId,
        principalId: otherPrincipalId,
        contextMode: 'PLATFORM',
      });
      // Even an internal callback cannot move a proof to another otherwise eligible Participant.
      const direct = await repository.beginOidc(configuration, participantId);
      await expect(
        repository.completeOidc(direct.authorization.transactionId, direct.custody, {
          state: direct.authorization.state,
          nonce: direct.authorization.nonce,
          issuer: provider.issuer,
          audience: provider.clientId,
          authorizedParty: provider.clientId,
          subject: 'verified-account',
          participantId: otherParticipantId,
          issuedAt: new Date(Date.now() - 1000),
          expiresAt: new Date(Date.now() + 60000),
        }),
      ).rejects.toMatchObject({ code: 'PC-AUTH-0002' });
    } finally {
      await app.close();
      await provider.close();
      await Promise.all([admin.end(), runtime.end()]);
    }
  },
);

// AF30-REQ-DD61729C5D0483C87D5DCB89: external account identity is exact.
// This tests session admission; global IdentitySubject and membership linking
// retain separate acceptance obligations.
integration(
  'fences OIDC session admission to one active exact stored account binding',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const runtime = new Pool({ connectionString: runtimeUrl });
    const repository = new PostgresIdentityRepository(runtime);
    const participantId = randomUUID();
    const principalId = randomUUID();
    const otherPrincipalId = randomUUID();
    const issuer = 'https://binding.openpc.example';
    const audience = 'openpc-binding-test';
    try {
      // Initial identity trust only. Every tested session uses the real owner.
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch)
      values ($1,'OIDC binding fixture','ACTIVE',1)`,
        [participantId],
      );
      for (const id of [principalId, otherPrincipalId])
        await admin.query(
          `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
        values ($1,$2,'USER',$3,'ACTIVE',1)`,
          [id, participantId, id],
        );
      const bindings = [
        ['ExactAccount', 'ACTIVE', '-1 hour', null, principalId],
        ['revoked', 'REVOKED', '-1 hour', null, principalId],
        ['future', 'ACTIVE', '1 hour', null, principalId],
        ['expired', 'ACTIVE', '-2 hour', '-1 hour', principalId],
        ['ambiguous', 'ACTIVE', '-1 hour', null, principalId],
        ['ambiguous', 'ACTIVE', '-1 hour', null, otherPrincipalId],
      ];
      for (const [subject, state, from, until, id] of bindings)
        await admin.query(
          `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,
        state,credential_epoch,valid_from,valid_until) values ($1,$2,'OIDC_SUBJECT',$3,$4,$5,$6,1,
        clock_timestamp()+$7::interval,clock_timestamp()+$8::interval)`,
          [participantId, id, issuer, subject, audience, state, from, until],
        );

      async function attempt(subject: string, target = principalId, clientId = audience) {
        const started = await repository.beginOidc({
          issuer,
          clientId,
          redirectUri: 'https://control.openpc.example/callback',
        });
        const callback = {
          state: started.authorization.state,
          nonce: started.authorization.nonce,
          issuer,
          subject,
          audience: clientId,
          authorizedParty: clientId,
          principalId: target,
          participantId,
          issuedAt: new Date(Date.now() - 1000),
          expiresAt: new Date(Date.now() + 60_000),
        };
        return {
          started,
          complete: () =>
            repository.completeOidc(started.authorization.transactionId, started.custody, callback),
        };
      }
      for (const [subject, target, clientId] of [
        ['missing', principalId, audience],
        ['exactaccount', principalId, audience],
        ['ExactAccount ', principalId, audience],
        ['ExactAccount', otherPrincipalId, audience],
        ['ExactAccount', principalId, 'other-client'],
        ['revoked', principalId, audience],
        ['future', principalId, audience],
        ['expired', principalId, audience],
        ['ambiguous', principalId, audience],
      ]) {
        const pending = await attempt(subject!, target, clientId);
        await expect(pending.complete()).rejects.toMatchObject({ code: 'PC-AUTH-0002' });
        expect(
          (
            await admin.query(
              `select consumed_at from control.oidc_transaction where transaction_id=$1`,
              [pending.started.authorization.transactionId],
            )
          ).rows[0].consumed_at,
        ).toBeNull();
      }
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.session where participant_id=$1`,
            [participantId],
          )
        ).rows[0].count,
      ).toBe(0);
      const valid = await attempt('ExactAccount');
      const session = await valid.complete();
      expect(session).toMatchObject({ principalId, participantId, state: 'ACTIVE' });
      await expect(valid.complete()).rejects.toMatchObject({ code: 'PC-AUTH-0002' });
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.session where participant_id=$1`,
            [participantId],
          )
        ).rows[0].count,
      ).toBe(1);
    } finally {
      await Promise.all([admin.end(), runtime.end()]);
    }
  },
);
