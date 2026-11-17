import { Pool } from 'pg';
import { createHash, sign } from 'node:crypto';
import { digest as governanceDigest, sha } from './public-governance-client.js';
import { canonicalAuthorizationDigest } from '../../../services/identity-service/src/contracts/authorization.js';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

integration(
  'discovers only active direct privacy contexts for the authenticated actor and rechecks current authority',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const participantId = id(),
      rootPrivacy = id(),
      allowed = id(),
      unassigned = id(),
      expired = id(),
      foreign = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      fixture = await contractAdministrationFixture(admin, runtimeUrl!, participantId, rootPrivacy);
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Other context tenant','ACTIVE',1)`,
        [foreign],
      );
      for (const [privacy, owner] of [
        [allowed, participantId],
        [unassigned, participantId],
        [expired, participantId],
        [id(), foreign],
      ])
        await admin.query(
          `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1::text::uuid,$2,$1::text,'PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
          [privacy, owner],
        );
      const authority = [];
      for (const privacy of [allowed, expired]) {
        const envelope = id(),
          assignment = id(),
          role = id();
        authority.push({ privacy, envelope, assignment, role });
        await admin.query(
          `insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
        values($1::text::uuid,$2,'urn:openpc:role:'||$1::text,$1::text,array['ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'],'BOOTSTRAP',$3)`,
          [role, participantId, fixture.makerId],
        );
        await admin.query(
          `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
        authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
        maker_checker_required,step_up_required,onward_delegation_depth)
        select $1::text::uuid,participant_id,principal_id,maker_principal_id,checker_principal_id,1,0,'ACTIVE',clock_timestamp()-interval '1 hour',
        case when $5::boolean then clock_timestamp()-interval '1 minute' else null end,semantic_cbor,sha256(convert_to($1::text,'UTF8')),cose_sign1,
        array[$2]::text[],array['ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'],array['*'],risk_classes,false,false,0
        from control.authority_envelope where participant_id=$3 and principal_id=$4 order by authority_envelope_id limit 1`,
          [envelope, privacy, participantId, fixture.makerId, privacy === expired],
        );
        await admin.query(
          `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,
        valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id)
        select $1,participant_id,principal_id,authority_envelope_id,0,semantic_digest,tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),
        'ACTIVE',principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,false,false,0,$3 from control.authority_envelope where authority_envelope_id=$2`,
          [assignment, envelope, `urn:openpc:role:${role}`],
        );
      }
      const { sessionToken } = await fixture.service.login('operator');
      const validate = async (token = sessionToken) => {
        const response = await fetch(
          `${fixture!.service.identityUrl}/internal/v1/local/session/validate`,
          {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${fixture!.service.identityInternalToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ sessionToken: token }),
          },
        );
        return { status: response.status, body: await response.json() };
      };
      const initial = await validate();
      expect(initial.status).toBe(200);
      expect(initial.body.availableContexts).toEqual(
        [allowed, rootPrivacy]
          .sort()
          .map((privacyDomainId) => ({ participantId, privacyDomainId })),
      );
      const allowedAuthority = authority.find((a) => a.privacy === allowed)!;
      // A discovery response is not cached authority. Withdrawal must remove the hint.
      await admin.query(
        `update control.assignment set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp() where assignment_id=$1`,
        [allowedAuthority.assignment],
      );
      const changed = await validate();
      expect(changed.status).toBe(200);
      expect(changed.body.availableContexts).toEqual([
        { participantId, privacyDomainId: rootPrivacy },
      ]);
      await admin.query(
        `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='context-discovery-test',row_version=row_version+1 where session_id=$1`,
        [sessionToken.split('.')[1]],
      );
      expect((await validate()).status).toBe(401);
    } finally {
      await fixture?.close();
      await admin.end();
    }
  },
  30000,
);

// These are downstream SQL admission checks on independently issued fixture
// sessions. They do not seed approvals, WebAuthn proofs or retained sessions.
const sessionRuntimeRoleSql = `
  select current_user as name, r.rolcanlogin, r.rolsuper, r.rolbypassrls,
         pg_has_role(current_user,'openpc_control_runtime','USAGE') as inherited_runtime,
         current_setting('row_security')='on' as row_security_on,
         c.relrowsecurity, c.relforcerowsecurity,
         has_table_privilege(current_user,'control.session','SELECT') as can_select,
         has_table_privilege(current_user,'control.session','INSERT') as can_insert,
         has_table_privilege(current_user,'control.session','UPDATE') as can_update
    from pg_roles r cross join pg_class c join pg_namespace n on n.oid=c.relnamespace
   where r.rolname=current_user and n.nspname='control' and c.relname='session'`;
const expectedSessionRuntimeRole = {
  name: 'openpc_identity_runtime',
  rolcanlogin: true,
  rolsuper: false,
  rolbypassrls: false,
  inherited_runtime: true,
  row_security_on: true,
  relrowsecurity: true,
  relforcerowsecurity: true,
  can_select: true,
  can_insert: true,
  can_update: true,
};

// Keep full bytes in memory and compare in SQL. Assertion output contains only
// booleans, so a failure cannot dump opaque token digests or CSRF secrets.
const sessionCustodySql = `jsonb_build_object(
  'sessions',(select coalesce(jsonb_agg(to_jsonb(s) order by s.session_id),'[]'::jsonb)
    from control.session s where s.participant_id=$1),
  'outbox',(select coalesce(jsonb_agg(to_jsonb(e) order by to_jsonb(e)::text),'[]'::jsonb)
    from control.outbox_event e where e.participant_id=$1),
  'idempotency',(select coalesce(jsonb_agg(to_jsonb(i) order by to_jsonb(i)::text),'[]'::jsonb)
    from control.idempotency_record i where i.participant_id=$1),
  'evidence',(select coalesce(jsonb_agg(to_jsonb(e) order by to_jsonb(e)::text),'[]'::jsonb)
    from control.mutation_evidence e where e.participant_id=$1))`;

const sessionFamilyInsertColumnsSql = `
  session_id,participant_id,principal_id,context_mode,privacy_domain_id,context_epoch,
  opaque_token_digest,state,authority_epoch,participant_epoch,delegation_epoch,session_epoch,
  refresh_family_id,refresh_token_digest,refresh_used,csrf_secret,issued_at,last_seen_at,
  idle_expires_at,absolute_expires_at,client_fingerprint_digest,
  duration_profile,idle_timeout_ms,absolute_timeout_ms`;

integration.each([
  {
    name: 'rejects a coherent issuance and absolute-deadline extension under the scoped runtime role',
    loginRole: 'viewer' as const,
    replacementId: false,
    replacementPrincipal: false,
    rotateBeforeInsert: false,
    sql: `update control.session
      set issued_at=issued_at+interval '1 minute',last_seen_at=last_seen_at+interval '1 minute',
          idle_expires_at=idle_expires_at+interval '1 minute',
          absolute_expires_at=absolute_expires_at+interval '1 minute',
          row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and session_id=$2 returning session_id`,
  },
  {
    name: 'rejects refresh-family identity replacement under the scoped runtime role',
    replacementId: true,
    replacementPrincipal: false,
    rotateBeforeInsert: false,
    sql: `update control.session set refresh_family_id=$3,
      row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and session_id=$2 returning session_id`,
  },
  {
    name: 'rejects a coherent duration-policy replacement on an already issued session',
    replacementId: false,
    replacementPrincipal: false,
    rotateBeforeInsert: false,
    sql: `update control.session
      set duration_profile='LOCAL_QA_10X',idle_timeout_ms=18000000,absolute_timeout_ms=432000000,
          absolute_expires_at=issued_at+interval '120 hours',
          idle_expires_at=least(last_seen_at+interval '5 hours',issued_at+interval '120 hours'),
          row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and session_id=$2 returning session_id`,
  },
  {
    name: 'rejects a new same-family row with coherently shifted issuance and absolute deadlines',
    replacementId: true,
    replacementPrincipal: false,
    rotateBeforeInsert: true,
    sql: `insert into control.session (${sessionFamilyInsertColumnsSql})
      select $3::uuid,participant_id,principal_id,context_mode,privacy_domain_id,context_epoch,
        sha256(convert_to($3::text||':session','UTF8')),'ACTIVE',
        authority_epoch,participant_epoch,delegation_epoch,session_epoch+1,
        refresh_family_id,sha256(convert_to($3::text||':refresh','UTF8')),false,
        sha256(convert_to($3::text||':csrf','UTF8')),
        issued_at+interval '1 minute',last_seen_at+interval '1 minute',
        idle_expires_at+interval '1 minute',absolute_expires_at+interval '1 minute',
        client_fingerprint_digest,duration_profile,idle_timeout_ms,absolute_timeout_ms
      from control.session where participant_id=$1 and session_id=$2 returning session_id`,
  },
  {
    name: 'rejects a new same-family row for another valid principal in the same Participant',
    replacementId: true,
    replacementPrincipal: true,
    rotateBeforeInsert: true,
    sql: `insert into control.session (${sessionFamilyInsertColumnsSql})
      select $3::uuid,participant_id,$4::uuid,context_mode,privacy_domain_id,context_epoch,
        sha256(convert_to($3::text||':session','UTF8')),'ACTIVE',
        authority_epoch,participant_epoch,delegation_epoch,session_epoch+1,
        refresh_family_id,sha256(convert_to($3::text||':refresh','UTF8')),false,
        sha256(convert_to($3::text||':csrf','UTF8')),
        issued_at,last_seen_at,idle_expires_at,absolute_expires_at,
        client_fingerprint_digest,duration_profile,idle_timeout_ms,absolute_timeout_ms
      from control.session where participant_id=$1 and session_id=$2 returning session_id`,
  },
])(
  '$name',
  async (testCase) => {
    const { sql, replacementId, replacementPrincipal, rotateBeforeInsert } = testCase;
    const loginRole = ('loginRole' in testCase ? testCase.loginRole : undefined) ?? 'operator';
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const participantId = id(),
      privacyDomainId = id(),
      attemptedSessionId = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
      );
      const session = await fixture.service.login(loginRole);
      const principalId =
        loginRole === 'viewer' ? fixture.governance.checker.principalId : fixture.makerId;
      expect(session.sessionToken === `${participantId}.${session.sessionId}`).toBe(true);
      const original = await admin.query(
        'select to_jsonb(s) as session from control.session s where participant_id=$1 and session_id=$2',
        [participantId, session.sessionId],
      );
      expect(original.rowCount).toBe(1);
      const before = await admin.query(`select ${sessionCustodySql} as custody`, [participantId]);
      const checkerId = fixture.governance.checker.principalId;
      await runScopedTransaction(
        runtime,
        { participantId, privacyDomainId, actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' },
        id,
        async (client) => {
          expect((await client.query(sessionRuntimeRoleSql)).rows).toEqual([
            expectedSessionRuntimeRole,
          ]);
          // A missing grant, wrong context or invisible target must fail this
          // preflight, rather than count as a successful duration-guard denial.
          const visible = await client.query(
            `select session_id,principal_id,context_mode,privacy_domain_id,state,duration_profile,
              idle_timeout_ms::text,absolute_timeout_ms::text,
              step_up_verified_at is not distinct from ($3::jsonb->>'step_up_verified_at')::timestamptz as original_step_up,
              to_jsonb(s)=$3::jsonb as original_bytes
             from control.session s where participant_id=$1 and session_id=$2`,
            [participantId, session.sessionId, original.rows[0]!.session],
          );
          expect(visible.rows).toEqual([
            {
              session_id: session.sessionId,
              principal_id: principalId,
              context_mode: 'PARTICIPANT',
              privacy_domain_id: privacyDomainId,
              state: 'ACTIVE',
              duration_profile: 'C17',
              idle_timeout_ms: '1800000',
              absolute_timeout_ms: '43200000',
              original_step_up: true,
              original_bytes: true,
            },
          ]);
          if (loginRole === 'viewer') {
            // The real viewer login issues no step-up proof. Retain that NULL;
            // moving an operator's issuance forward would independently
            // invalidate its original proof under session_step_up_ck.
            expect(
              (
                await client.query(
                  `with projected as (
                    select s.*,
                      issued_at+interval '1 minute' as projected_issued_at,
                      last_seen_at+interval '1 minute' as projected_last_seen_at,
                      idle_expires_at+interval '1 minute' as projected_idle_expires_at,
                      absolute_expires_at+interval '1 minute' as projected_absolute_expires_at
                    from control.session s where participant_id=$1 and session_id=$2
                  )
                  select step_up_verified_at is null as no_step_up,
                    projected_issued_at>issued_at and
                      projected_absolute_expires_at>absolute_expires_at as issuance_and_deadline_extended,
                    projected_last_seen_at>=projected_issued_at as seen_order,
                    projected_idle_expires_at=least(
                      projected_last_seen_at+idle_timeout_ms*interval '1 millisecond',
                      projected_absolute_expires_at) as idle_equation,
                    projected_absolute_expires_at=
                      projected_issued_at+absolute_timeout_ms*interval '1 millisecond' as absolute_equation,
                    duration_profile='C17' and idle_timeout_ms=1800000 and
                      absolute_timeout_ms=43200000 as normal_profile,
                    projected_idle_expires_at<=projected_absolute_expires_at as expiry_order,
                    step_up_verified_at is null or step_up_verified_at between
                      projected_issued_at and projected_absolute_expires_at as step_up_valid
                  from projected`,
                  [participantId, session.sessionId],
                )
              ).rows,
            ).toEqual([
              {
                no_step_up: true,
                issuance_and_deadline_extended: true,
                seen_order: true,
                idle_equation: true,
                absolute_equation: true,
                normal_profile: true,
                expiry_order: true,
                step_up_valid: true,
              },
            ]);
          }
          if (replacementPrincipal) {
            expect(
              (
                await client.query(
                  `select principal_id from control.principal
                where participant_id=$1 and principal_id=$2 and state='ACTIVE' and authority_epoch=1`,
                  [participantId, checkerId],
                )
              ).rows,
            ).toEqual([{ principal_id: checkerId }]);
          }
          const parameters = [participantId, session.sessionId];
          if (replacementId) parameters.push(attemptedSessionId);
          if (replacementPrincipal) parameters.push(checkerId);
          await client.query('savepoint session_guard_denial');
          if (rotateBeforeInsert) {
            // Match the owning rotation order: an old-row revocation precedes
            // successor insertion. The SQL savepoint must restore both steps;
            // this does not stand in for public refresh governance or proofs.
            expect(
              (
                await client.query(
                  `update control.session set state='REVOKED',refresh_used=true,
                revoked_at=clock_timestamp(),revoked_reason='duration-family-rollback',
                row_version=row_version+1,updated_at=clock_timestamp()
                where participant_id=$1 and session_id=$2 returning state,refresh_used`,
                  [participantId, session.sessionId],
                )
              ).rows,
            ).toEqual([{ state: 'REVOKED', refresh_used: true }]);
          }
          await expect(client.query(sql, parameters)).rejects.toMatchObject({
            code: 'P0001',
            message: 'PC-AUTH-0005-SESSION-DURATION',
          });
          await client.query('rollback to savepoint session_guard_denial');
          await client.query('release savepoint session_guard_denial');
          expect(
            (
              await client.query(
                `select to_jsonb(s)=$3::jsonb as unchanged from control.session s
              where participant_id=$1 and session_id=$2`,
                [participantId, session.sessionId, original.rows[0]!.session],
              )
            ).rows,
          ).toEqual([{ unchanged: true }]);
          expect(
            (
              await client.query(
                'select count(*)::integer as count from control.session where participant_id=$1 and session_id=$2',
                [participantId, attemptedSessionId],
              )
            ).rows,
          ).toEqual([{ count: 0 }]);
        },
      );
      // Compare after the scoped transaction COMMIT, not from another
      // connection while a possibly changed row is still uncommitted.
      expect(
        (
          await admin.query(`select ${sessionCustodySql}=$2::jsonb as unchanged`, [
            participantId,
            before.rows[0]!.custody,
          ])
        ).rows,
      ).toEqual([{ unchanged: true }]);
    } finally {
      try {
        await fixture?.close();
      } finally {
        await Promise.all([runtime.end(), admin.end()]);
      }
    }
  },
  30000,
);

integration(
  'allows same-policy SQL session touches, absolute clamping and revocation while retaining issuance custody',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const participantId = id(),
      privacyDomainId = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
      );
      const session = await fixture.service.login('operator');
      const admitted = await fetch(
        `${fixture.service.identityUrl}/internal/v1/local/session/validate`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${fixture.service.identityInternalToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ sessionToken: session.sessionToken }),
          signal: AbortSignal.timeout(5000),
        },
      );
      expect(admitted.status).toBe(200);
      await admitted.arrayBuffer();
      const original = await admin.query(
        'select to_jsonb(s) as session from control.session s where participant_id=$1 and session_id=$2',
        [participantId, session.sessionId],
      );
      expect(original.rowCount).toBe(1);
      const before = await admin.query(`select ${sessionCustodySql} as custody`, [participantId]);
      await runScopedTransaction(
        runtime,
        { participantId, privacyDomainId, actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1' },
        id,
        async (client) => {
          expect((await client.query(sessionRuntimeRoleSql)).rows).toEqual([
            expectedSessionRuntimeRole,
          ]);
          expect(
            (
              await client.query(
                `select state,duration_profile,idle_timeout_ms::text,absolute_timeout_ms::text,
              to_jsonb(s)=$3::jsonb as original_bytes from control.session s
              where participant_id=$1 and session_id=$2`,
                [participantId, session.sessionId, original.rows[0]!.session],
              )
            ).rows,
          ).toEqual([
            {
              state: 'ACTIVE',
              duration_profile: 'C17',
              idle_timeout_ms: '1800000',
              absolute_timeout_ms: '43200000',
              original_bytes: true,
            },
          ]);
          const touched = await client.query(
            `with touch as (select greatest(last_seen_at,statement_timestamp()) as seen
              from control.session where participant_id=$1 and session_id=$2)
             update control.session s
              set last_seen_at=touch.seen,
                  idle_expires_at=least(touch.seen+s.idle_timeout_ms*interval '1 millisecond',s.absolute_expires_at),
                  row_version=s.row_version+1,updated_at=clock_timestamp()
              from touch where s.participant_id=$1 and s.session_id=$2
              returning s.last_seen_at>=s.issued_at as seen_order,
                s.idle_expires_at=least(s.last_seen_at+s.idle_timeout_ms*interval '1 millisecond',s.absolute_expires_at) as idle_equation,
                (to_jsonb(s)-ARRAY['last_seen_at','idle_expires_at','row_version','updated_at'])=
                  ($3::jsonb-ARRAY['last_seen_at','idle_expires_at','row_version','updated_at']) as custody_preserved`,
            [participantId, session.sessionId, original.rows[0]!.session],
          );
          expect(touched.rows).toEqual([
            { seen_order: true, idle_equation: true, custody_preserved: true },
          ]);
          // Exercise the SQL clamp on this fresh independent row. Its original
          // absolute deadline is unchanged; this is not an elapsed-time or
          // public-session expiry qualification.
          const clamped = await client.query(
            `update control.session s
              set last_seen_at=absolute_expires_at-interval '1 millisecond',
                  idle_expires_at=absolute_expires_at,row_version=row_version+1,updated_at=clock_timestamp()
              where participant_id=$1 and session_id=$2
              returning idle_expires_at=absolute_expires_at as clamped,
                (to_jsonb(s)-ARRAY['last_seen_at','idle_expires_at','row_version','updated_at'])=
                  ($3::jsonb-ARRAY['last_seen_at','idle_expires_at','row_version','updated_at']) as custody_preserved`,
            [participantId, session.sessionId, original.rows[0]!.session],
          );
          expect(clamped.rows).toEqual([{ clamped: true, custody_preserved: true }]);
          const revoked = await client.query(
            `update control.session s
              set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='session-duration-regression',
                  row_version=row_version+1,updated_at=clock_timestamp()
              where participant_id=$1 and session_id=$2
              returning state,revoked_at is not null as revoked,
                (to_jsonb(s)-ARRAY['last_seen_at','idle_expires_at','row_version','updated_at','state','revoked_at','revoked_reason'])=
                  ($3::jsonb-ARRAY['last_seen_at','idle_expires_at','row_version','updated_at','state','revoked_at','revoked_reason']) as custody_preserved`,
            [participantId, session.sessionId, original.rows[0]!.session],
          );
          expect(revoked.rows).toEqual([
            { state: 'REVOKED', revoked: true, custody_preserved: true },
          ]);
        },
      );
      const retained = await admin.query(
        `select state,revoked_at is not null as revoked,idle_expires_at=absolute_expires_at as clamped,
          (to_jsonb(s)-ARRAY['last_seen_at','idle_expires_at','row_version','updated_at','state','revoked_at','revoked_reason'])=
            ($3::jsonb-ARRAY['last_seen_at','idle_expires_at','row_version','updated_at','state','revoked_at','revoked_reason']) as custody_preserved
          from control.session s where participant_id=$1 and session_id=$2`,
        [participantId, session.sessionId, original.rows[0]!.session],
      );
      expect(retained.rows).toEqual([
        { state: 'REVOKED', revoked: true, clamped: true, custody_preserved: true },
      ]);
      expect(
        (
          await admin.query(
            `select (${sessionCustodySql}-'sessions')=($2::jsonb-'sessions') as effects_unchanged`,
            [participantId, before.rows[0]!.custody],
          )
        ).rows,
      ).toEqual([{ effects_unchanged: true }]);
      expect(
        (
          await admin.query(
            `select (select jsonb_agg(to_jsonb(s) order by s.session_id) from control.session s
            where s.participant_id=$1 and s.session_id<>$3::uuid)
          is not distinct from
          (select jsonb_agg(value order by (value->>'session_id')::uuid)
            from jsonb_array_elements($2::jsonb->'sessions')
            where (value->>'session_id')::uuid<>$3::uuid) as siblings_unchanged`,
            [participantId, before.rows[0]!.custody, session.sessionId],
          )
        ).rows,
      ).toEqual([{ siblings_unchanged: true }]);
      const denied = await fetch(
        `${fixture.service.identityUrl}/internal/v1/local/session/validate`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${fixture.service.identityInternalToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ sessionToken: session.sessionToken }),
          signal: AbortSignal.timeout(5000),
        },
      );
      expect(denied.status).toBe(401);
      await denied.arrayBuffer();
    } finally {
      try {
        await fixture?.close();
      } finally {
        await Promise.all([runtime.end(), admin.end()]);
      }
    }
  },
  30000,
);

integration.each(['maker', 'checker'] as const)(
  'refreshes an exact Platform session through current authority, replay and restart for %s',
  async (actorName) => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const participantId = id(),
      privacyDomainId = id(),
      platformContextId = id();
    const foreignParticipantId = id(),
      foreignPrivacyDomainId = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    const hash = (value: string) => createHash('sha256').update(value).digest('hex');
    try {
      // Independent initial trust. No refresh result or business approval is seeded.
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Platform session maintenance','ACTIVE',1)",
        [participantId],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Session maintenance root','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [privacyDomainId, participantId],
      );
      await admin.query(
        'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
        [participantId, privacyDomainId],
      );
      await admin.query(
        "insert into control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version) values($1,$2,'ACTIVE',1,1)",
        [platformContextId, participantId],
      );
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Foreign session scope','ACTIVE',1)",
        [foreignParticipantId],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Foreign session root','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [foreignPrivacyDomainId, foreignParticipantId],
      );
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
        {
          existingScope: true,
          initialPlatformContext: { id: platformContextId, epoch: '1' },
        },
      );
      const service = fixture.service,
        actor = fixture.governance[actorName];
      const origin = new URL(service.identityUrl).origin,
        host = new URL(service.identityUrl).host;
      const actionIntentId = 'ACT-IDENTITY_CREATE_SESSION-V1';
      const reason = 'Rotate the current Platform session.';
      const idempotencyKey = `platform-refresh-${id()}`;
      const internal = async (path: string, body: unknown) =>
        fetch(`${service.identityUrl}${path}`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${service.identityInternalToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(5000),
        });
      const contextInput = (token: string, key = idempotencyKey) => ({
        sessionToken: token,
        actionIntentId,
        catalogOperationId: 'ID-OP-SESSION-REFRESH',
        idempotencyKey: key,
        candidateDigest: canonicalAuthorizationDigest({
          sessionId: token.split('.')[1],
          operation: 'REFRESH',
          reason,
        }),
        origin,
        host,
      });
      const before = (
        await admin.query(
          `select context_mode,privacy_domain_id,context_epoch,principal_id,absolute_expires_at,
          authority_epoch,participant_epoch,delegation_epoch,refresh_family_id
          from control.session where participant_id=$1 and session_id=$2`,
          [participantId, actor.sessionId],
        )
      ).rows[0]!;
      expect(before.context_mode).toBe('PLATFORM');
      expect(before.privacy_domain_id).toBeNull();
      const contextResponse = await internal(
        '/internal/v1/local/session/command-context',
        contextInput(actor.sessionToken),
      );
      expect(contextResponse.status).toBe(200);
      const context = await contextResponse.json();
      expect(context.privacyDomainId).toBe(privacyDomainId);
      expect(context.replay).toBe(false);
      const csrfResponse = await fetch(`${service.identityUrl}/api/v1/session/csrf`, {
        method: 'POST',
        headers: {
          'Cookie': `__Host-openpc_session=${actor.sessionToken}`,
          'Content-Type': 'application/json',
          'Origin': origin,
        },
        body: JSON.stringify({ actionIntentId }),
        signal: AbortSignal.timeout(5000),
      });
      expect(csrfResponse.status).toBe(200);
      const csrf = (await csrfResponse.json()).csrfToken as string;
      const command = {
        actionIntentId,
        actionIntentDigest: context.actionIntentDigest,
        targetRef: `urn:openpc:resource:${actor.sessionId}`,
        inputDigest: contextInput(actor.sessionToken).candidateDigest,
        expectedRevision: context.revision,
        reason,
      };
      const refresh = async (
        token: string,
        body = command,
        key = idempotencyKey,
        csrfToken = csrf,
        selectedPrivacy = privacyDomainId,
      ) =>
        fetch(`${service.identityUrl}/api/v1/session/refresh`, {
          method: 'POST',
          headers: {
            'Cookie': `__Host-openpc_session=${token}`,
            'Content-Type': 'application/json',
            'Origin': origin,
            'X-CSRF-Token': csrfToken,
            'X-Request-ID': id(),
            'X-Correlation-ID': id(),
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${selectedPrivacy}`,
            'OpenPC-Action-Intent-Digest': context.actionIntentDigest,
            'If-Match': `"${canonicalAuthorizationDigest({ resourceType: 'session', revision: body.expectedRevision, sessionId: body.targetRef.split(':').at(-1) })}"`,
            'Idempotency-Key': key,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10000),
        });
      const refreshed = await refresh(actor.sessionToken);
      expect(refreshed.status).toBe(202);
      const operation = await refreshed.json();
      expect(operation.state).toBe('SUCCEEDED');
      const cookie = refreshed.headers.get('set-cookie')!;
      const nextToken = /__Host-openpc_session=([^;]+)/u.exec(cookie)?.[1];
      expect(nextToken).toBeTypeOf('string');
      expect(hash(nextToken!)).not.toBe(hash(actor.sessionToken));
      const nextId = nextToken!.split('.')[1]!;
      const after = (
        await admin.query(
          `select context_mode,privacy_domain_id,context_epoch,principal_id,absolute_expires_at,
          authority_epoch,participant_epoch,delegation_epoch,refresh_family_id
          from control.session where participant_id=$1 and session_id=$2`,
          [participantId, nextId],
        )
      ).rows[0]!;
      expect(after).toEqual(before);
      const old = await internal('/internal/v1/local/session/validate', {
        sessionToken: actor.sessionToken,
      });
      expect(old.status).toBe(401);
      const current = await internal('/internal/v1/local/session/validate', {
        sessionToken: nextToken,
      });
      expect(current.status).toBe(200);
      const currentBody = await current.json();
      expect(currentBody.contextMode).toBe('PLATFORM');
      expect(currentBody.privacyDomainId).toBeUndefined();
      expect(currentBody.principalId).toBe(actor.principalId);
      await service.restartIdentity();
      // Resolve replay context from the original revoked session, without a caller-supplied domain.
      const replayContextResponse = await internal(
        '/internal/v1/local/session/command-context',
        contextInput(actor.sessionToken),
      );
      expect(replayContextResponse.status).toBe(200);
      const replayContext = await replayContextResponse.json();
      expect(replayContext.replay).toBe(true);
      expect(replayContext.privacyDomainId).toBe(privacyDomainId);
      const replayed = await refresh(
        actor.sessionToken,
        command,
        idempotencyKey,
        replayContext.replayCsrfToken,
      );
      expect(replayed.status).toBe(202);
      expect(await replayed.json()).toEqual(operation);
      expect(hash(replayed.headers.get('set-cookie')!)).toBe(hash(cookie));
      const evidence = async () =>
        (
          await admin.query(
            `select count(*)::int count from control.mutation_evidence where participant_id=$1 and principal_id=$2 and catalog_operation_id='ID-OP-SESSION-REFRESH'`,
            [participantId, actor.principalId],
          )
        ).rows[0]!.count;
      expect(await evidence()).toBe(1);
      const wrongScope = await refresh(
        actor.sessionToken,
        command,
        idempotencyKey,
        replayContext.replayCsrfToken,
        foreignPrivacyDomainId,
      );
      expect(wrongScope.status).toBe(401);
      expect(await evidence()).toBe(1);
      // Withdraw this test grant; the runtime must re-read it before any new rotation.
      await admin.query(
        "update control.assignment set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and principal_id=$2 and state='ACTIVE'",
        [participantId, actor.principalId],
      );
      const deniedKey = `platform-denied-${id()}`;
      const deniedContextResponse = await internal(
        '/internal/v1/local/session/command-context',
        contextInput(nextToken!, deniedKey),
      );
      expect(deniedContextResponse.status).toBe(200);
      const deniedContext = await deniedContextResponse.json();
      const deniedCsrfResponse = await fetch(`${service.identityUrl}/api/v1/session/csrf`, {
        method: 'POST',
        headers: {
          'Cookie': `__Host-openpc_session=${nextToken}`,
          'Content-Type': 'application/json',
          'Origin': origin,
        },
        body: JSON.stringify({ actionIntentId }),
        signal: AbortSignal.timeout(5000),
      });
      expect(deniedCsrfResponse.status).toBe(200);
      const denied = await refresh(
        nextToken!,
        {
          ...command,
          targetRef: `urn:openpc:resource:${nextId}`,
          expectedRevision: deniedContext.revision,
          inputDigest: contextInput(nextToken!, deniedKey).candidateDigest,
        },
        deniedKey,
        (await deniedCsrfResponse.json()).csrfToken,
      );
      expect(denied.status).toBe(403);
      expect(await evidence()).toBe(1);
      const stillActive = (
        await admin.query(
          'select state from control.session where participant_id=$1 and session_id=$2',
          [participantId, nextId],
        )
      ).rows[0]!;
      expect(stillActive.state).toBe('ACTIVE');
    } finally {
      await fixture?.close();
      await admin.end();
    }
  },
  60_000,
);

integration.each(['maker', 'checker'] as const)(
  'enters Participant context from an ordinary Platform session through real WebAuthn for %s',
  async (actorName) => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const participantId = id(),
      privacyDomainId = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
      );
      const { client, devices } = fixture.governance;
      const actor = fixture.governance[actorName];
      const device = devices.get(actor.principalId)!;
      const origin = fixture.service.identityUrl;
      const intent = 'ACT-IDENTITY_CREATE_SESSION-V1';
      const selection = { participantId, privacyDomainId };
      const resourceDigest = governanceDigest(selection);
      const rpIdHash = `sha256:${sha(new URL(origin).hostname).toString('hex')}`;
      // Independent initial session context, before challenge/verification or
      // business effects. The principal remains an ordinary USER, as at OIDC entry.
      await admin.query(
        "update control.session set context_mode='PLATFORM',privacy_domain_id=null where session_id=$1",
        [actor.sessionId],
      );
      expect(
        (
          await admin.query('select kind from control.principal where principal_id=$1', [
            actor.principalId,
          ])
        ).rows[0].kind,
      ).toBe('USER');
      const witness = async () =>
        (
          await admin.query(
            `select jsonb_build_object(
        'credential',(select jsonb_build_object('state',state,'counter',authenticator_sign_count,'version',row_version) from control.credential where participant_id=$1 and credential_id=$3),
        'challenge',(select coalesce(jsonb_agg(jsonb_build_object('id',mfa_challenge_id,'resource',resource_id,'consumed',consumed_at,'used',used_at,'expiry',expires_at) order by mfa_challenge_id),'[]'::jsonb) from control.mfa_challenge where participant_id=$1 and principal_id=$2),
        'session',(select jsonb_build_object('mode',context_mode,'epoch',context_epoch,'stepUp',step_up_mfa_challenge_id,'state',state,'version',row_version) from control.session where session_id=$4),
        'evidence',(select count(*) from control.mutation_evidence where participant_id=$1),
        'outbox',(select count(*) from control.outbox_event where participant_id=$1)) as value`,
            [participantId, actor.principalId, device.credentialId, actor.sessionId],
          )
        ).rows[0].value;
      const unchanged = async (before: unknown) =>
        expect(JSON.stringify(await witness()) === JSON.stringify(before)).toBe(true);
      const csrf = await client.csrf(actor, intent, origin);
      const challenge = async (
        resource = participantId,
        digest = resourceDigest,
        session = actor,
      ) =>
        client.request(
          `${origin}/v1/identity/webauthn/assertion/challenge`,
          session,
          { actionIntentId: intent, resourceId: resource, resourceDigest: digest, rpIdHash },
          { 'X-CSRF-Token': session === actor ? csrf : await client.csrf(session, intent, origin) },
        );
      for (const resource of [id(), actor.sessionId, privacyDomainId]) {
        const before = await witness();
        expect((await challenge(resource)).status).toBe(403);
        await unchanged(before);
      }
      const first = await challenge();
      expect(first.status).toBe(200);
      expect(first.body.credentialIds).toContain(
        device.externalCredentialId ?? device.credentialId,
      );
      const signed = (body: Record<string, unknown>, counter: number, flags = 5) => {
        const clientData = Buffer.from(
          JSON.stringify({ type: 'webauthn.get', challenge: body.challenge, origin }),
        );
        const authenticatorData = Buffer.alloc(37);
        sha(new URL(origin).hostname).copy(authenticatorData);
        authenticatorData[32] = flags;
        authenticatorData.writeUInt32BE(counter, 33);
        return JSON.stringify({
          credentialId: device.externalCredentialId ?? device.credentialId,
          authenticatorData: authenticatorData.toString('base64url'),
          clientDataJson: clientData.toString('base64url'),
          signature: sign(
            'sha256',
            Buffer.concat([authenticatorData, sha(clientData)]),
            device.privateKey,
          ).toString('base64url'),
        });
      };
      const proof = (body: Record<string, unknown>, counter = 1) => ({
        actionIntentId: intent,
        resourceId: participantId,
        resourceDigest,
        rpIdHash,
        challenge: body.challenge,
        assertion: signed(body, counter),
      });
      const headers = async (session = actor) => ({
        'X-CSRF-Token': session === actor ? csrf : await client.csrf(session, intent, origin),
        'Idempotency-Key': `context-entry-${id()}`,
        'X-OpenPC-Aggregate-Version': (
          await admin.query('select row_version::text from control.session where session_id=$1', [
            session.sessionId,
          ])
        ).rows[0].row_version,
        'OpenPC-Action-Intent-Digest': client.actionDigests.get('ACT-IDENTITY_UPDATE_STEP_UP-V1')!,
      });
      const verify = async (
        body: unknown,
        requestHeaders?: Record<string, string>,
        session = actor,
      ) =>
        client.request(
          `${origin}/v1/identity/webauthn/assertion/verify`,
          session,
          body,
          requestHeaders ?? (await headers(session)),
        );
      for (const body of [
        { ...proof(first.body), resourceId: id() },
        { ...proof(first.body), resourceDigest: `sha256:${'a'.repeat(64)}` },
        { ...proof(first.body), rpIdHash: `sha256:${'b'.repeat(64)}` },
        { ...proof(first.body), assertion: signed(first.body, 1, 1) },
      ]) {
        const before = await witness();
        expect((await verify(body)).status).toBeGreaterThanOrEqual(400);
        await unchanged(before);
      }
      const wrongSession = fixture.governance[actorName === 'maker' ? 'checker' : 'maker'];
      const beforeWrongSession = await witness();
      expect(
        (await verify(proof(first.body), undefined, wrongSession)).status,
      ).toBeGreaterThanOrEqual(400);
      await unchanged(beforeWrongSession);
      await admin.query(
        "update control.mfa_challenge set expires_at=clock_timestamp()-interval '1 second' where participant_id=$1 and session_id=$2 and consumed_at is null",
        [participantId, actor.sessionId],
      );
      const beforeExpired = await witness();
      expect((await verify(proof(first.body))).status).toBeGreaterThanOrEqual(400);
      await unchanged(beforeExpired);
      const current = await challenge();
      expect(current.status).toBe(200);
      const body = proof(current.body);
      const verificationHeaders = await headers();
      const verified = await verify(body, verificationHeaders);
      expect(verified.status, JSON.stringify(verified.body)).toBe(200);
      const afterVerified = await witness();
      expect(String(afterVerified.credential.counter)).toBe('1');
      expect(afterVerified.session.mode).toBe('PLATFORM');
      expect(afterVerified.session.stepUp).not.toBeNull();
      expect((await verify(body, verificationHeaders)).status).toBeGreaterThanOrEqual(400);
      await unchanged(afterVerified);
      const selected = await client.request(`${origin}/api/v1/session/context`, actor, selection, {
        'X-CSRF-Token': csrf,
      });
      expect(selected.status, JSON.stringify(selected.body)).toBe(201);
      expect(selected.body.contextMode).toBe('PARTICIPANT');
      expect(selected.body.participantId).toBe(participantId);
      expect(selected.body.privacyDomainId).toBe(privacyDomainId);
      expect(selected.body.principalId).toBe(actor.principalId);
      const successor = {
        principalId: actor.principalId,
        sessionId: String(selected.body.sessionId),
        sessionToken: String(selected.body.sessionToken),
      };
      expect(successor.sessionId === actor.sessionId).toBe(false);
      const old = (
        await admin.query('select state,revoked_reason from control.session where session_id=$1', [
          actor.sessionId,
        ])
      ).rows[0];
      expect(old.state).toBe('REVOKED');
      expect(old.revoked_reason).toBe('context-rotation');
      const next = await challenge(participantId, resourceDigest, successor);
      expect(next.status).toBe(200);
      const nextHeaders = await headers(successor);
      if (actorName === 'maker')
        await admin.query(
          "update control.assignment set state='REVOKED',row_version=row_version+1 where participant_id=$1 and principal_id=$2",
          [participantId, actor.principalId],
        );
      else
        await admin.query(
          "update control.credential set state='REVOKED',credential_epoch=credential_epoch+1,row_version=row_version+1 where participant_id=$1 and credential_id=$2",
          [participantId, device.credentialId],
        );
      const beforeWithdrawal = await witness();
      expect(
        (await verify(proof(next.body, 2), nextHeaders, successor)).status,
      ).toBeGreaterThanOrEqual(400);
      await unchanged(beforeWithdrawal);
    } finally {
      await fixture?.close();
      await admin.end();
    }
  },
  30000,
);
