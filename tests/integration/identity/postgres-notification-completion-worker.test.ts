import {
  assertNotificationCompletionPhaseBindings,
  assertNotificationCompletionPhaseOnlyReceiptDenied,
  assertNotificationCompletionSharedDirectDenials,
} from './notification-completion-disposition-cases.js';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { TLSSocket } from 'node:tls';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationCompletionWorkerProfileClaims,
} from '../../../packages/security-kernel/src/index.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import {
  installInitialNotificationCompletionWorker,
  withdrawNotificationCompletionWorker,
  readNotificationCompletionWorkerOriginal,
} from '../../../services/control-api/src/notifications/completion-worker-installation.js';
import { assertNotificationCompletionWorkerInstallationLifecycle } from '../../../services/control-api/src/notifications/completion-worker-installation.test.js';
import { validateNotificationCompletionWorkerInstallation } from '../../../services/control-api/src/notifications/completion-worker-installation-contract.js';
import {
  withNotificationCompletionWorkerPeer,
  assertNotificationCompletionWorkerCurrent,
  admitNotificationCompletionDispositionPhase,
  installNotificationCompletionSqlBridge,
  type NotificationCompletionWorkerAdmission,
} from '../../../services/identity-service/src/domain/notification-completion-worker.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
it.runIf(adminUrl)(
  'rejects same-name validated CHECK replacement for every completion shared table constraint',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 1 });
    const client = await pool.connect();
    try {
      await client.query('select openpc.assert_notification_completion_disposition_shared_owner()');
      const { rows } = await client.query<{ table_name: string; constraint_name: string }>(
        `select t.relname as table_name,c.conname as constraint_name from pg_constraint c
         join pg_class t on t.oid=c.conrelid join pg_namespace n on n.oid=t.relnamespace
         where n.nspname='control' and c.contype='c' and t.relname=any($1::text[])
         order by t.relname,c.conname`,
        [
          [
            'notification_completion_disposition_signer_installation',
            'notification_completion_source',
            'notification_completion_attempt',
            'notification_completion_disposition_signing',
            'notification_completion_disposition',
            'notification_source_inbox',
            'notification_source_cursor',
          ],
        ],
      );
      expect(rows).toHaveLength(21);
      const quote = (value: string) => `"${value.replaceAll('"', '""')}"`;
      for (const row of rows) {
        await client.query('begin');
        try {
          await client.query(
            `alter table control.${quote(row.table_name)} drop constraint ${quote(row.constraint_name)}, add constraint ${quote(row.constraint_name)} check (true)`,
          );
          await expect(
            client.query('select openpc.assert_notification_completion_disposition_shared_owner()'),
          ).rejects.toThrow('NOTIFICATION-COMPLETION-SHARED-SCHEMA');
        } finally {
          await client.query('rollback');
        }
      }
      const trigger = await client.query<{ definition: string; type: number }>(
        `select pg_get_triggerdef(oid,false) definition,tgtype::integer type from pg_trigger
         where tgrelid='control.notification_completion_source'::regclass
         and tgname='notification_completion_source_truncate'`,
      );
      expect(trigger.rows[0]?.type).toBe(34);
      expect(trigger.rows[0]?.definition).toContain('BEFORE TRUNCATE');
      await client.query('begin');
      try {
        await client.query(
          'drop trigger notification_completion_source_truncate on control.notification_completion_source',
        );
        await client.query(
          trigger.rows[0]!.definition.replace('BEFORE TRUNCATE', 'AFTER TRUNCATE'),
        );
        await expect(
          client.query('select openpc.assert_notification_completion_disposition_shared_owner()'),
        ).rejects.toThrow('NOTIFICATION-COMPLETION-SHARED-OWNER');
      } finally {
        await client.query('rollback');
      }
      await client.query('select openpc.assert_notification_completion_disposition_shared_owner()');
    } finally {
      client.release();
      await pool.end();
    }
  },
);
it.runIf(adminUrl && runtimeUrl)(
  'enforces real completion-worker TLS, installation withdrawal, expiry and restored profile authority without consumer effects',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const owner = new Pool({
      connectionString: adminUrl,
      options: '-c role=openpc_control_owner',
      max: 1,
    });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    const keyFile = process.env.OPENPC_NOTIFICATION_COMPLETION_TEST_KEY_FILE;
    if (!keyFile) throw new Error('Completion native host trust missing');
    const bridgeKey = Buffer.from(readFileSync(keyFile, 'utf8').trim(), 'hex');
    installNotificationCompletionSqlBridge(runtime, bridgeKey);
    const participantId = id(),
      privacyDomainId = id(),
      principalId = id(),
      credentialId = id();
    const workloadId = `urn:openpc:workload:${id()}`;
    const tls = await runtimeSnapshotTlsFixture(
      `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`,
    );
    const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const spki = issuer.publicKey.export({ type: 'spki', format: 'der' });
    const key = issuer.privateKey.export({ type: 'pkcs8', format: 'der' });
    const tlsSpki = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
    const context = {
      participantId,
      privacyDomainId,
      actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    };
    const scope = { participantId, privacyDomainId };
    const make = (lifetime = 60000) => {
      const claims: NotificationCompletionWorkerProfileClaims = {
        environmentId: 'local-completion',
        participantId,
        privacyDomainId,
        profileId: id(),
        revision: '1',
        validFromMs: Date.now() - 1000,
        validUntilMs: Date.now() + lifetime,
        serviceId: 'LS-CONTROL-WORK',
        processRole: 'ROLE-CONTROL-WORKER',
        subscriptionId: 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1',
        principalId,
        workloadCredentialId: credentialId,
        workloadEpoch: '1',
        workloadId,
        workloadKeyDigest: evidenceKeyId(tlsSpki),
        producerTrustDigest: sha256('initial-completion-producer-trust'),
        maximumAttempts: 3,
        initialBackoffMs: 100,
        maximumBackoffMs: 1000,
        issuerKeyId: evidenceKeyId(spki),
      };
      const signed = signNotificationClaim(
        'NotificationCompletionWorkerProfileV1',
        key,
        spki,
        claims,
      );
      const {
        validFromMs,
        validUntilMs,
        maximumAttempts,
        initialBackoffMs,
        maximumBackoffMs,
        issuerKeyId,
        ...pins
      } = claims;
      void validFromMs;
      void validUntilMs;
      void maximumAttempts;
      void initialBackoffMs;
      void maximumBackoffMs;
      void issuerKeyId;
      return {
        pins: {
          ...pins,
          issuerSpkiHex: spki.toString('hex'),
          signedProfileDigest: sha256(signed.cose),
        },
        signed: {
          payloadHex: signed.payload.toString('hex'),
          coseHex: signed.cose.toString('hex'),
        },
        installationReference: 'local-initial-trust',
      };
    };
    const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime, systemClock));
    let app: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
    let current:
      { participantId: string; privacyDomainId: string; installationDigest: string } | undefined;
    let expireAt: number | undefined;
    const eventId = id();
    let escaped: NotificationCompletionWorkerAdmission | undefined;
    const original = make(),
      successor = make();
    const open = async () => {
      app = buildLocalWorkloadMtlsService(runtime, kernel, tls.server);
      app.post('/test/lifecycle', async (req) =>
        assertNotificationCompletionWorkerInstallationLifecycle({
          ownerPool: owner,
          runtimePool: runtime,
          kernel,
          socket: req.raw.socket as TLSSocket,
          successorSocket: req.raw.socket as TLSSocket,
          original,
          successor,
        }),
      );
      app.post('/test/current', async (req, reply) => {
        try {
          return await withNotificationCompletionWorkerPeer(
            runtime,
            kernel,
            req.raw.socket as TLSSocket,
            req.body,
            async (client, admission) => {
              await assertNotificationCompletionWorkerCurrent(admission, client, current!);
              if (expireAt)
                await new Promise((resolve) =>
                  setTimeout(resolve, Math.max(0, expireAt! - Date.now() + 25)),
                );
              return { installationDigest: admission.installation.installationDigest };
            },
          );
        } catch {
          return reply.code(403).send({ code: 'COMPLETION_WORKER_UNAVAILABLE' });
        }
      });
      app.post('/test/phase', async (req, reply) => {
        try {
          return await withNotificationCompletionWorkerPeer(
            runtime,
            kernel,
            req.raw.socket as TLSSocket,
            current,
            async (client, admission) => {
              escaped = admission;
              for (const phase of [
                'SOURCE',
                'CLAIM',
                'LIMIT',
                'FINISH',
                'PREPARE',
                'SIGN_CLAIM',
                'OBSERVE',
                'PUBLISH',
              ] as const) {
                await admitNotificationCompletionDispositionPhase(
                  admission,
                  client,
                  current!,
                  eventId,
                  phase,
                );
                await client.query(
                  'select openpc.require_notification_completion_disposition_authority($1,$2)',
                  [eventId, phase],
                );
                expect(
                  (
                    await client.query(
                      'select * from openpc.notification_completion_phase_binding($1,$2)',
                      [eventId, phase],
                    )
                  ).rows,
                ).toEqual([
                  {
                    installation_digest: admission.installation.installationDigest,
                    authority_digest: admission.authorityDigest,
                  },
                ]);
                await assertNotificationCompletionPhaseBindings({
                  client,
                  eventId,
                  phase,
                  admission,
                });
                await assertNotificationCompletionPhaseOnlyReceiptDenied(client, eventId, phase);
                if (phase === 'PUBLISH')
                  await assertNotificationCompletionSharedDirectDenials({
                    client,
                    eventId,
                    admission,
                  });
                if (phase === 'SOURCE') {
                  await client.query('savepoint wrong_phase');
                  await expect(
                    client.query(
                      'select openpc.require_notification_completion_disposition_authority($1,$2)',
                      [eventId, 'PUBLISH'],
                    ),
                  ).rejects.toThrow();
                  await client.query('rollback to savepoint wrong_phase');
                  await client.query('savepoint wrong_effect_phase');
                  await expect(
                    client.query(
                      'select openpc.check_notification_completion_effect_binding($1,$2,$3,$4)',
                      [
                        eventId,
                        'PUBLISH',
                        admission.installation.installationDigest,
                        admission.authorityDigest,
                      ],
                    ),
                  ).rejects.toMatchObject({ code: 'P0002' });
                  await client.query('rollback to savepoint wrong_effect_phase');
                }
              }
              await client.query('savepoint foreign_event');
              await expect(
                client.query(
                  'select openpc.require_notification_completion_disposition_authority($1,$2)',
                  [id(), 'SOURCE'],
                ),
              ).rejects.toThrow();
              await client.query('rollback to savepoint foreign_event');
              const mode = (req.body as { mode?: string }).mode;
              if (mode === 'rollback') throw new Error('deliberate phase rollback');
              if (mode === 'expiry') {
                await client.query('select pg_sleep(5.05)');
                await client.query(
                  'select openpc.require_notification_completion_disposition_authority($1,$2)',
                  [eventId, 'SOURCE'],
                );
              }
              if (mode === 'transaction') {
                await client.query('rollback');
                await client.query('begin');
                await client.query(
                  "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
                  [participantId, privacyDomainId, id()],
                );
                await assertNotificationCompletionWorkerCurrent(admission, client, current!);
              }
              return { phases: 8 };
            },
          );
        } catch {
          return reply.code(403).send({ code: 'COMPLETION_PHASE_UNAVAILABLE' });
        }
      });
      return app.listen({ host: '127.0.0.1', port: 0 });
    };
    try {
      // Dedicated initial native trust. The runtime role cannot read this key.
      expect(
        (
          await admin.query(
            "select count(*)::int count from control.notification_completion_admission_key where database_role='openpc_identity_runtime' and verifier_secret=$1",
            [bridgeKey],
          )
        ).rows,
      ).toEqual([{ count: 1 }]);
      // Only initial identity and public-key trust are bootstrap fixtures. No
      // occurrence, completion event, inbox, cursor or business effect is seeded.
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Completion admission','ACTIVE',1)",
        [participantId],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'completion','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE')",
        [privacyDomainId, participantId],
      );
      await admin.query(
        "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Completion consumer','ACTIVE',1)",
        [principalId, participantId],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-completion-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          credentialId,
          participantId,
          principalId,
          `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`,
          workloadId,
          Buffer.from(sha256(tlsSpki).slice(7), 'hex'),
          tlsSpki,
          Buffer.from(sha256(tls.parsed.raw).slice(7), 'hex'),
          new Date(tls.parsed.validFrom),
          new Date(tls.parsed.validTo),
        ],
      );
      let address = await open();
      const result = await tls.post(`${address}/test/lifecycle`, {});
      expect(result.status).toBe(200);
      current = (result.body as { successor: typeof current }).successor;
      expect(current).toBeDefined();
      expect(await tls.post(`${address}/test/phase`, {})).toMatchObject({
        status: 200,
        body: { phases: 8 },
      });
      for (const mode of ['rollback', 'transaction', 'expiry'])
        expect(await tls.post(`${address}/test/phase`, { mode })).toMatchObject({ status: 403 });
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.notification_completion_phase_admission where participant_id=$1',
            [participantId],
          )
        ).rows,
      ).toEqual([{ count: 0 }]);
      for (const operation of [
        (c: import('pg').PoolClient) =>
          c.query('select openpc.notification_completion_verified_receipt($1,$2)', [
            eventId,
            'PUBLISH',
          ]),
        (c: import('pg').PoolClient) =>
          c.query('select openpc.check_notification_completion_effect_binding($1,$2,$3,$4)', [
            eventId,
            'SOURCE',
            escaped!.installation.installationDigest,
            escaped!.authorityDigest,
          ]),
        (c: import('pg').PoolClient) =>
          c.query('select openpc.require_notification_completion_disposition_authority($1,$2)', [
            eventId,
            'SOURCE',
          ]),
        (c: import('pg').PoolClient) =>
          c.query('select openpc.admit_notification_completion_phase($1,$2,$3)', [
            Buffer.from('{}'),
            Buffer.alloc(32),
            Buffer.alloc(32),
          ]),
        (c: import('pg').PoolClient) =>
          c.query('select verifier_secret from control.notification_completion_admission_key'),
        (c: import('pg').PoolClient) =>
          c.query('insert into control.notification_completion_phase_admission default values'),
        (c: import('pg').PoolClient) =>
          admitNotificationCompletionDispositionPhase(escaped!, c, current!, eventId, 'SOURCE'),
      ])
        await expect(
          runScopedTransaction<unknown>(runtime, context, id, operation),
        ).rejects.toThrow();
      expect(await tls.post(`${address}/test/current`, current)).toMatchObject({ status: 200 });
      await app!.close();
      address = await open();
      expect(await tls.post(`${address}/test/current`, current)).toMatchObject({ status: 200 });
      await expect(tls.post(`${address}/test/current`, current, null)).rejects.toThrow();
      for (const bad of [
        { ...current, privacyDomainId: id() },
        { ...current, participantId: id() },
        { ...current, installationDigest: sha256('foreign') },
      ])
        expect(await tls.post(`${address}/test/current`, bad)).toMatchObject({ status: 403 });
      await expect(
        runScopedTransaction(runtime, context, id, (c) =>
          installInitialNotificationCompletionWorker(c, make()),
        ),
      ).rejects.toThrow();
      for (const [pool, code] of [
        [runtime, '42501'],
        [owner, 'P0001'],
      ] as const) {
        await expect(
          runScopedTransaction(pool, context, id, (c) =>
            c.query(
              `
          insert into control.installed_notification_completion_worker
          (participant_id,privacy_domain_id,profile_id,principal_id,workload_credential_id,
          service_id,subscription_id,producer_trust_digest,signed_profile_digest,
          installation,installation_bytes,installation_digest)
          values($1,$2,$3,$4,$5,'LS-CONTROL-WORK','SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1',
          $6,$6,'{}'::jsonb,convert_to('{}','UTF8'),$6)`,
              [participantId, privacyDomainId, id(), principalId, credentialId, sha256('{}')],
            ),
          ),
        ).rejects.toMatchObject({ code });
      }
      for (const mutation of [
        'alter table control.installed_notification_completion_worker no force row level security',
        'alter table control.installed_notification_completion_worker disable trigger notification_completion_worker_installation_guard',
        'grant update on control.installed_notification_completion_worker to openpc_control_runtime',
        'create or replace function openpc.guard_notification_completion_worker_installation() returns trigger language plpgsql security invoker set search_path=pg_catalog as $$ begin return new; end $$',
      ]) {
        const c = await admin.connect();
        try {
          await c.query('begin');
          await c.query('set local role openpc_control_owner');
          await c.query(mutation);
          await c.query('set local role openpc_control_runtime');
          await expect(
            c.query('select openpc.assert_notification_completion_worker_installation_owner()'),
          ).rejects.toThrow();
        } finally {
          await c.query('rollback');
          c.release();
        }
      }
      await runScopedTransaction(owner, context, id, (c) =>
        withdrawNotificationCompletionWorker(c, current),
      );
      expect(await tls.post(`${address}/test/phase`, {})).toMatchObject({ status: 403 });
      const expiring = make(1500);
      const validated = validateNotificationCompletionWorkerInstallation(expiring, Date.now());
      current = {
        ...scope,
        installationDigest: await runScopedTransaction(owner, context, id, (c) =>
          installInitialNotificationCompletionWorker(c, expiring),
        ),
      };
      expireAt = validated.profile.validUntilMs;
      expect(await tls.post(`${address}/test/current`, current)).toMatchObject({ status: 403 });
      const history = await runScopedTransaction(runtime, context, id, (c) =>
        readNotificationCompletionWorkerOriginal(c, current),
      );
      expect(history.original.input).toEqual(expiring);
      const effects = await admin.query(
        "select (select count(*) from control.outbox_event where participant_id=$1 and event_type='NotificationDeliveryCompleted')::int events,(select count(*) from control.work_item where participant_id=$1)::int work,(select count(*) from control.notification_source_inbox where participant_id=$1)::int inbox",
        [participantId],
      );
      expect(effects.rows).toEqual([{ events: 0, work: 0, inbox: 0 }]);
    } finally {
      if (app) await app.close();
      await tls.close();
      await runtime.end();
      await owner.end();
      await admin.end();
      key.fill(0);
      bridgeKey.fill(0);
    }
  },
  30000,
);

it.runIf(adminUrl && runtimeUrl)(
  'authenticates actual completion registration and rejects transactional guard, grant, FK and generated-binding tampering',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 1 });
    const client = await pool.connect();
    try {
      await client.query('select openpc.assert_notification_completion_disposition_shared_owner()');
      const defects = [
        'alter table control.notification_completion_disposition no force row level security',
        'alter table control.notification_source_inbox disable trigger notification_source_inbox_effect_guard',
        'alter table control.notification_source_cursor disable trigger notification_source_cursor_effect_pair',
        'alter table control.work_item disable trigger notification_completion_remediation_complete',
        'alter table control.work_item disable trigger work_item_lifecycle',
        'alter table control.work_item disable trigger work_item_effect_receipt',
        'alter table control.notification_source_inbox drop constraint notification_inbox_completion_operation_fk',
        'alter table control.notification_source_inbox drop constraint notification_inbox_operation_fk',
        'alter table control.notification_source_inbox alter column completion_admission_operation_id set expression as (NULL::uuid)',
        'alter table control.notification_source_inbox drop constraint notification_inbox_state_ck; alter table control.notification_source_inbox add constraint notification_inbox_state_ck check (true)',
        'alter policy privacy_domain_isolation on control.notification_completion_source using (true) with check (true)',
        'grant update(initial_worker) on control.notification_completion_source to openpc_control_runtime',
        'revoke update(effective_limit) on control.notification_completion_source from openpc_control_runtime',
        'grant insert on control.notification_completion_disposition_signer_installation to openpc_control_runtime',
        'grant insert on control.notification_completion_disposition to openpc_control_worker',
        'grant execute on function openpc.publish_notification_completion_disposition_effects(uuid) to public',
        'alter function openpc.check_notification_completion_receipt_admission(uuid,text,jsonb) security definer',
        `create or replace function openpc.check_notification_completion_receipt_admission(event uuid,phase text,observation jsonb) returns void language plpgsql volatile security invoker set search_path=pg_catalog as $$ begin return; end $$`,
      ];
      for (const defect of defects) {
        await client.query('begin');
        try {
          await client.query('set local role openpc_control_owner');
          await client.query(defect);
          await expect(
            client.query('select openpc.assert_notification_completion_disposition_shared_owner()'),
          ).rejects.toMatchObject({
            code: 'P0001',
            message: expect.stringMatching(/^NOTIFICATION-COMPLETION-SHARED-/u),
          });
        } finally {
          await client.query('rollback');
        }
      }
      await client.query('select openpc.assert_notification_completion_disposition_shared_owner()');
    } finally {
      client.release(true);
      await pool.end();
    }
  },
);

it.runIf(runtimeUrl)(
  'retains privileged completion trust installation and limits runtime updates to the declared transition fields',
  async () => {
    const pool = new Pool({ connectionString: runtimeUrl, max: 1 });
    try {
      await pool.query('select openpc.assert_notification_completion_disposition_shared_owner()');
      const result = await pool.query<{
        trust_write: boolean;
        source_limit: boolean;
        source_identity: boolean;
        terminal_update: boolean;
        inbox_result: boolean;
        inbox_identity: boolean;
        cursor_position: boolean;
        cursor_identity: boolean;
      }>(`select
        has_any_column_privilege(current_user,'control.notification_completion_disposition_signer_installation','INSERT,UPDATE') trust_write,
        has_column_privilege(current_user,'control.notification_completion_source','effective_limit','UPDATE') source_limit,
        has_column_privilege(current_user,'control.notification_completion_source','initial_worker','UPDATE') source_identity,
        has_any_column_privilege(current_user,'control.notification_completion_disposition','UPDATE') terminal_update,
        has_column_privilege(current_user,'control.notification_source_inbox','admission_operation_id','UPDATE') inbox_result,
        has_column_privilege(current_user,'control.notification_source_inbox','event_id','UPDATE') inbox_identity,
        has_column_privilege(current_user,'control.notification_source_cursor','last_sequence','UPDATE') cursor_position,
        has_column_privilege(current_user,'control.notification_source_cursor','partition','UPDATE') cursor_identity`);
      expect(result.rows).toEqual([
        {
          trust_write: false,
          source_limit: true,
          source_identity: false,
          terminal_update: false,
          inbox_result: true,
          inbox_identity: false,
          cursor_position: true,
          cursor_identity: false,
        },
      ]);
    } finally {
      await pool.end();
    }
  },
);
