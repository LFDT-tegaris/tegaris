import { createHash } from 'node:crypto';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const url = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const integration = url ? it : it.skip;

// Connected SQL/privilege preflight. No business row, authority, signing grant,
// work-item transition or consumer acknowledgement is fabricated here.
integration(
  'installs the closed work-item state projection and narrow receipt grants',
  async () => {
    const admin = new Pool({ connectionString: url, max: 1 });
    const creator = id();
    const source = {
      kind: 'DELIVERY_FAILURE',
      state: 'OPEN',
      assignee_principal_id: null,
      resource_ref: `urn:openpc:resource:${id()}`,
      payload_digest: `\\x${'31'.repeat(32)}`,
      reason: 'Delivery unavailable — metadata only',
      created_by_principal_id: creator,
      claimed_by_principal_id: null,
      completed_by_principal_id: null,
    };
    try {
      const { rows } = await admin.query(
        `select openpc.work_item_business_projection(jsonb_populate_record(null::control.work_item,$1::jsonb)) as projection`,
        [source],
      );
      expect(rows[0].projection).toEqual({
        0: source.kind,
        1: source.state,
        2: source.resource_ref,
        3: { bytes: '31'.repeat(32) },
        4: { bytes: createHash('sha256').update(source.reason, 'utf8').digest('hex') },
        5: { bytes: creator.replaceAll('-', '') },
        6: 0,
        8: 0,
        10: 0,
      });
      for (const signature of [
        'openpc.work_item_business_projection(control.work_item)',
        'openpc.assert_work_item_receipt(control.audit_occurrence)',
      ]) {
        for (const role of [
          'openpc_control_runtime',
          'openpc_control_reader',
          'openpc_control_worker',
          'openpc_control_platform_runtime',
        ]) {
          const privilege = await admin.query(
            `select has_function_privilege($1,$2,'EXECUTE') as allowed`,
            [role, signature],
          );
          expect(privilege.rows[0].allowed, `${role}: ${signature}`).toBe(
            role === 'openpc_control_runtime',
          );
        }
      }
      const trigger = await admin.query(
        `select tgdeferrable,tginitdeferred,pg_get_expr(tgqual,tgrelid) as predicate
       from pg_trigger where tgrelid='control.work_item'::regclass and tgname='work_item_effect_receipt'`,
      );
      expect(trigger.rowCount).toBe(1);
      expect(trigger.rows[0].tgdeferrable).toBe(true);
      expect(trigger.rows[0].tginitdeferred).toBe(true);
      for (const action of [
        'ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
        'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
        'ACT-OPERATIONS_UPDATE_CLAIM-V1',
        'ACT-OPERATIONS_UPDATE_COMPLETE-V1',
      ])
        expect(trigger.rows[0].predicate).toContain(action);
    } finally {
      await admin.end();
    }
  },
);
