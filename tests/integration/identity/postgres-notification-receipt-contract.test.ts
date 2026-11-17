import { Pool } from 'pg';
import { readFile, readdir } from 'node:fs/promises';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const url = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = url && runtimeUrl ? it : it.skip;
integration(
  'requires the installed native completion owner and denies an event with no original outcome',
  async () => {
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const client = await runtime.connect();
    const participant = id(),
      privacy = id(),
      occurrence = id();
    try {
      const role = await client.query(
        'select not rolsuper and not rolbypassrls safe from pg_roles where rolname=current_user',
      );
      expect(role.rows[0]?.safe).toBe(true);
      const installed = await client.query(
        "select to_regprocedure('openpc.check_notification_delivery_completed_event(control.outbox_event)') checker",
      );
      expect(installed.rows[0]?.checker).toBe(
        'openpc.check_notification_delivery_completed_event(control.outbox_event)',
      );
      await client.query('begin');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        [participant, privacy, id()],
      );
      // No source state is seeded. The real BEFORE INSERT dispatcher must reach
      // the mandatory native owner, never admit through the request proof or
      // defer an unchecked publication to a later foreign-key failure.
      await expect(
        client.query(
          `insert into control.outbox_event
        (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
         proof_kind,sequence_namespace,business_sequence,data_schema_uri,source,subject,
         correlation_id,causation_id,payload_cbor,payload_digest,occurred_at)
        values($1,$2,$3,'NotificationDeliveryCompleted','notification-occurrence',$4,
         'NOTIFICATION_DELIVERY_COMPLETION_REFERENCE','NOTIFICATION_DELIVERY_COMPLETED_V1',1,
         'urn:openpc:test:unproved','urn:openpc:test:unproved','urn:openpc:test:unproved',
         $5,$6,decode('00','hex'),sha256(decode('00','hex')),clock_timestamp())`,
          [participant, privacy, id(), occurrence, id(), id()],
        ),
      ).rejects.toMatchObject({
        code: 'P0002',
        message: 'query returned no rows',
      });
    } finally {
      await client.query('rollback');
      client.release(true);
      await runtime.end();
    }
  },
);
integration(
  'reapplies the generated notification security tail without duplicate policies or triggers',
  async () => {
    const directory = new URL('../../../migrations/postgres/control-api/', import.meta.url);
    const latest = (await readdir(directory))
      .filter((name) => /^[0-9]{4}_.*\.sql$/u.test(name))
      .sort()
      .at(-1);
    if (!latest) throw new Error('Missing generated Control migration');
    const parts = (await readFile(new URL(latest, directory), 'utf8')).split(
      '-- OPENPC CONTROL-API SECURITY TAIL',
    );
    expect(parts).toHaveLength(2);
    const admin = new Pool({ connectionString: url, max: 1 });
    const client = await admin.connect();
    try {
      await client.query('begin');
      await client.query('set local role openpc_control_owner');
      await client.query(parts[1]!);
      const policies = await client.query(`select count(*)::int n from pg_policy
      where polrelid='control.installed_notification_channel'::regclass and polname='notification_channel_installer'`);
      expect(policies.rows).toEqual([{ n: 1 }]);
      const triggers = await client.query(
        `select count(*)::int n from pg_trigger
      where tgenabled='O' and tgname=any($1::text[])`,
        [
          [
            'notification_channel_installation_guard',
            'notification_candidate_guard',
            'notification_verification_attempt_guard',
            'notification_verification_row_guard',
            'notification_endpoint_mutation_guard',
            'notification_endpoint_effect_receipt',
            'notification_verification_attachment',
          ],
        ],
      );
      expect(triggers.rows).toEqual([{ n: 7 }]);
      const grants = await client.query(`select
      has_table_privilege('openpc_control_runtime','control.installed_notification_channel','SELECT') readable,
      has_table_privilege('openpc_control_runtime','control.installed_notification_channel','INSERT,UPDATE,DELETE') mutable`);
      expect(grants.rows).toEqual([{ readable: true, mutable: false }]);
    } finally {
      try {
        await client.query('rollback');
      } finally {
        client.release(true);
        await admin.end();
      }
    }
  },
);
integration(
  'installs exact notification projections, forced scope isolation and unconditional signed effect checks',
  async () => {
    const admin = new Pool({ connectionString: url, max: 1 });
    try {
      for (const resource of [null, `urn:openpc:resource:${id()}`]) {
        const item = {
          severity: 'WARNING',
          state: 'UNREAD',
          message_key: 'evidence.export.completed',
          resource_ref: resource,
          candidate_digest: `sha256:${'31'.repeat(32)}`,
        };
        const result = await admin.query(
          `select openpc.notification_business_projection(jsonb_populate_record(null::control.notification,$1::jsonb)) as projection`,
          [item],
        );
        expect(result.rows[0].projection).toEqual({
          0: 'WARNING',
          1: 'UNREAD',
          2: item.message_key,
          3: resource === null ? 0 : 1,
          ...(resource === null ? {} : { 4: resource }),
          5: { bytes: '31'.repeat(32) },
        });
      }
      for (const role of [
        'openpc_control_runtime',
        'openpc_control_reader',
        'openpc_control_worker',
        'openpc_control_platform_runtime',
      ]) {
        for (const signature of [
          'openpc.notification_business_projection(control.notification)',
          'openpc.assert_notification_receipt(control.audit_occurrence)',
        ]) {
          const grant = await admin.query(
            `select has_function_privilege($1,$2,'EXECUTE') allowed`,
            [role, signature],
          );
          expect(grant.rows[0].allowed, `${role}:${signature}`).toBe(
            role === 'openpc_control_runtime',
          );
        }
        for (const privilege of ['INSERT', 'UPDATE', 'DELETE']) {
          const grant = await admin.query(
            `select has_table_privilege($1,'control.notification',$2) allowed`,
            [role, privilege],
          );
          expect(grant.rows[0].allowed, `${role}:${privilege}`).toBe(
            role === 'openpc_control_runtime' && privilege !== 'DELETE',
          );
        }
      }
      const table = await admin.query(
        `select relrowsecurity,relforcerowsecurity from pg_class where oid='control.notification'::regclass`,
      );
      expect(table.rows[0]).toEqual({ relrowsecurity: true, relforcerowsecurity: true });
      const trigger = await admin.query(
        `select tgdeferrable,tginitdeferred,tgqual from pg_trigger where tgrelid='control.notification'::regclass and tgname='notification_effect_receipt'`,
      );
      expect(trigger.rows).toEqual([{ tgdeferrable: true, tginitdeferred: true, tgqual: null }]);
    } finally {
      await admin.end();
    }
  },
);

integration(
  'rejects unsigned creation, wrong actions and foreign scope through the installed runtime role without effects',
  async () => {
    const admin = new Pool({ connectionString: url, max: 1 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const participant = id(),
      privacy = id(),
      foreignPrivacy = id();
    try {
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Notification scope trust','ACTIVE',1)`,
        [participant],
      );
      for (const scope of [privacy, foreignPrivacy])
        await admin.query(
          `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,$1::uuid::text,'PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
          [scope, participant],
        );
      for (const scenario of ['UNSIGNED', 'WRONG_ACTION', 'FOREIGN_SCOPE'] as const) {
        const client = await runtime.connect();
        try {
          await client.query('begin');
          await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
            participant,
            privacy,
            id(),
            scenario === 'WRONG_ACTION'
              ? 'ACT-NOTIFICATIONS_READ_RESOURCE-V1'
              : 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1',
          ]);
          const insert = () =>
            client.query(
              `insert into control.notification(notification_id,participant_id,privacy_domain_id,severity,message_key,candidate_digest) values($1,$2,$3,'WARNING','evidence.export.completed',$4)`,
              [
                id(),
                participant,
                scenario === 'FOREIGN_SCOPE' ? foreignPrivacy : privacy,
                `sha256:${'31'.repeat(32)}`,
              ],
            );
          if (scenario === 'UNSIGNED') {
            expect((await insert()).rowCount).toBe(1);
            await client.query(
              "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)",
              [participant, privacy, id(), 'ACT-NOTIFICATIONS_READ_RESOURCE-V1'],
            );
            await expect(client.query('set constraints all immediate')).rejects.toThrow(
              'query returned no rows',
            );
          } else
            await expect(insert()).rejects.toThrow(
              scenario === 'WRONG_ACTION' ? 'DATA-6021-NOTIFICATION-CREATE' : 'PC-AUTH-0005',
            );
        } finally {
          await client.query('rollback');
          client.release();
        }
        const count = await admin.query(
          `select (select count(*)::int from control.notification where participant_id=$1) metadata,(select count(*)::int from control.audit_occurrence where participant_id=$1) receipts,(select count(*)::int from control.outbox_event where participant_id=$1) events`,
          [participant],
        );
        expect(count.rows[0]).toEqual({ metadata: 0, receipts: 0, events: 0 });
      }
    } finally {
      await runtime.end();
      await admin.end();
    }
  },
);
