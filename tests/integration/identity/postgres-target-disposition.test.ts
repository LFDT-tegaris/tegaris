import { createHash, createHmac, randomBytes } from 'node:crypto';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.js';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../../../services/control-api/src/configuration/persistence/scoped-read.js';
import { closeFixtureResources } from './close-fixture-resources.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;
const tables = ['admission', 'delivery', 'acknowledgement'].map(
  (suffix) => `control.runtime_target_disposition_${suffix}`,
);

async function context(client: PoolClient) {
  await client.query('begin');
  await client.query(
    "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)",
    [id(), id(), id()],
  );
}

// Real installed SQL security boundary only. No activation/approval/ACK is
// seeded, and this case cannot establish end-to-end withdrawal or restoration.
integration(
  'keeps disposition admission, native proof and original records closed under SQL tampering',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const owner = await admin.connect();
    const client = await worker.connect();
    try {
      expect(
        (
          await client.query(
            'select rolsuper,rolbypassrls from pg_roles where rolname=current_user',
          )
        ).rows[0],
      ).toEqual({ rolsuper: false, rolbypassrls: false });
      await client.query('select openpc.assert_runtime_target_disposition_owner()');
      // Compile the installed ACK lookup against its real table and local
      // declarations even when this empty trust fixture has no activation.
      // No row or receipt is seeded: the public journey proves the ACK effect.
      // This catches PL/pgSQL name collisions hidden behind earlier denials.
      const definition = (
        await client.query<{ body: string }>(
          "select pg_get_functiondef('openpc.commit_runtime_target_disposition(text,bytea,bytea,bytea)'::regprocedure) body",
        )
      ).rows[0]!.body;
      const declarations = /DECLARE[\s\S]*?\nBEGIN/u.exec(definition)?.[0];
      const lookup =
        /SELECT \* INTO STRICT delivery FROM control\.runtime_target_disposition_delivery d[\s\S]*?;/u.exec(
          definition,
        )?.[0];
      expect(declarations).toBeDefined();
      expect(lookup).toBeDefined();
      await context(client);
      await client.query(
        `do $ack_lookup$ ${declarations} ${lookup!.replace('INTO STRICT', 'INTO')} END $ack_lookup$;`,
      );
      await client.query('rollback');
      await context(client);
      await expect(
        client.query(
          `do $ack_collision$ ${declarations!.replaceAll('receipt_claims', 'claims')} ${lookup!.replace('INTO STRICT', 'INTO').replaceAll('receipt_claims', 'claims')} END $ack_collision$;`,
        ),
      ).rejects.toMatchObject({ code: '42702', message: 'column reference "claims" is ambiguous' });
      await client.query('rollback');
      // Format/expiry validation is distinct from native admission. These calls
      // cannot establish a Fact lease, insert a disposition or enable serving.
      const nowNs = BigInt(Date.now()) * 1_000_000n;
      const capsuleDigest = '12'.repeat(32);
      const factCustody = {
        version: 1,
        capsuleDigest,
        factStateDigest: '23'.repeat(32),
        dependencyDigest: '34'.repeat(32),
        originalRecordsDigest: '45'.repeat(32),
        validUntilNs: String(nowNs + 30_000_000_000n),
      };
      const factProof = {
        sourceMode: 'FACT_BOUND',
        capsuleDigest,
        capsuleValidUntilNs: String(nowNs + 60_000_000_000n),
        factCustody,
      };
      for (const proof of [{ sourceMode: 'FACT_FREE' }, factProof])
        await client.query('select openpc.check_runtime_target_fact_proof($1)', [proof]);
      for (const proof of [
        null,
        {},
        { sourceMode: 'FACT_FREE', factCustody: null },
        { ...factProof, sourceMode: 'CALLER_READY' },
        { ...factProof, factCustody: undefined },
        { ...factProof, factCustody: [] },
        ...[
          { extra: true },
          { version: 2 },
          { capsuleDigest: '99'.repeat(32) },
          { factStateDigest: 'AA'.repeat(32) },
          { dependencyDigest: 'sha256:' + '34'.repeat(32) },
          { originalRecordsDigest: null },
          { validUntilNs: Number(nowNs) },
          { validUntilNs: '0' },
          { validUntilNs: '01' },
          { validUntilNs: String(nowNs - 1n) },
          { validUntilNs: String(nowNs + 61_000_000_000n) },
          { validUntilNs: '18446744073709551616' },
        ].map((change) => ({ ...factProof, factCustody: { ...factCustody, ...change } })),
      ])
        await expect(
          client.query('select openpc.check_runtime_target_fact_proof($1)', [proof]),
        ).rejects.toMatchObject({ code: 'P0001' });
      expect(
        (
          await owner.query(
            "select count(*)::integer count from control.runtime_target_disposition_key where database_role='openpc_local_control_worker'",
          )
        ).rows[0]?.count,
      ).toBe(1);
      for (const table of tables) {
        await expect(client.query(`insert into ${table} default values`)).rejects.toMatchObject({
          code: '42501',
        });
        await expect(client.query(`delete from ${table}`)).rejects.toMatchObject({ code: '42501' });
        await expect(client.query(`truncate ${table}`)).rejects.toMatchObject({ code: '42501' });
      }
      await expect(
        client.query('select verifier_secret from control.runtime_target_disposition_key'),
      ).rejects.toMatchObject({ code: '42501' });

      await context(client);
      await expect(
        client.query('select * from openpc.begin_runtime_target_withdrawal($1,$2,$3,$4,$5)', [
          id(),
          id(),
          'untrusted-worker',
          `sha256:${'ab'.repeat(32)}`,
          0,
        ]),
      ).rejects.toMatchObject({ code: 'P0001' });
      await client.query('rollback');
      for (const kind of ['DELIVERY', 'ACK', 'RESTORE']) {
        await context(client);
        await expect(
          client.query('select openpc.commit_runtime_target_disposition($1,$2,$3,$4)', [
            kind,
            Buffer.from('{}'),
            Buffer.alloc(32),
            Buffer.alloc(32),
          ]),
        ).rejects.toMatchObject({ code: 'P0001', message: 'PC-AUTH-0005' });
        await client.query('rollback');
      }

      // Native restoration proof is a distinct MAC domain and is bound to
      // the transaction which actually holds current-source locks. These tests
      // reject before any fabricated target/cause can enter business state.
      const key = (
        await owner.query<{ verifier_secret: Buffer }>(
          "select verifier_secret from control.runtime_target_disposition_key where database_role='openpc_local_control_worker'",
        )
      ).rows[0]!.verifier_secret;
      const nonce = randomBytes(32);
      const proof = {
        version: 1,
        transactionId: '0',
        targetId: id(),
        withdrawalDigest: 'ab'.repeat(32),
        capsuleDigest: 'bc'.repeat(32),
        capsuleValidUntilNs: (BigInt(Date.now() + 30000) * 1000000n).toString(),
        policyGenerationDigest: 'cd'.repeat(32),
        workloadId: `urn:openpc:workload:${id()}`,
        identityManifestDigest: 'de'.repeat(32),
        sourceMode: 'FACT_FREE',
        originalReceiptDigest: 'ef'.repeat(32),
        originalTokenDigest: 'fa'.repeat(32),
      };
      const wire = Buffer.from(canonicalJson(proof));
      const mac = (domain: string) =>
        createHmac('sha256', key)
          .update(domain)
          .update(createHash('sha256').update(wire).digest())
          .update(nonce)
          .digest();
      for (const domain of [
        'OPENPC_TARGET_DISPOSITION_DELIVERY_V1',
        'OPENPC_TARGET_DISPOSITION_RESTORE_ADMISSION_V1',
      ]) {
        await context(client);
        await expect(
          client.query('select * from openpc.begin_runtime_target_unstarted_restore($1,$2,$3)', [
            wire,
            nonce,
            mac(domain),
          ]),
        ).rejects.toMatchObject({
          code: 'P0001',
          message: domain.endsWith('RESTORE_ADMISSION_V1')
            ? 'TARGET-DISPOSITION-RESTORE-PROOF'
            : 'PC-AUTH-0005',
        });
        await client.query('rollback');
      }
      for (const domain of [
        'OPENPC_TARGET_DISPOSITION_RESTORE_ADMISSION_V1',
        'OPENPC_TARGET_DISPOSITION_ACTIVATION_ADMISSION_V1',
      ]) {
        await context(client);
        await expect(
          client.query(
            'select * from openpc.begin_runtime_target_activation_confirmation($1,$2,$3)',
            [wire, nonce, mac(domain)],
          ),
        ).rejects.toMatchObject({
          code: 'P0001',
          message: domain.endsWith('ACTIVATION_ADMISSION_V1')
            ? 'TARGET-DISPOSITION-ACTIVATION-PROOF'
            : 'PC-AUTH-0005',
        });
        await client.query('rollback');
      }
      key.fill(0);

      // Readback/revalidation cannot create missing admission or replace its
      // original proof. Bad selectors fail before any business row is present.
      for (const selectors of [
        [null, 1, 'sha256:' + 'ab'.repeat(32), null],
        [id(), 0, 'sha256:' + 'ab'.repeat(32), null],
        [id(), 1, null, null],
      ]) {
        await context(client);
        await expect(
          client.query(
            'select openpc.lock_runtime_target_disposition_issuance($1,$2,$3,$4)',
            selectors,
          ),
        ).rejects.toMatchObject({ code: 'P0001', message: 'TARGET-DISPOSITION-ISSUANCE-CONTEXT' });
        await client.query('rollback');
      }

      // Each defect is isolated in a rollback-only transaction. The gate must
      // fail before accepting any wire or changing a disposition record.
      const defects = [
        'create or replace function openpc.lock_runtime_target_disposition_issuance(target uuid,wanted_revision bigint,wanted_digest text,worker text) returns void language plpgsql volatile security definer set search_path=pg_catalog set row_security=on as $$begin return; end$$',
        'create or replace function openpc.lock_runtime_target_current_sources(target uuid,expected_source jsonb,proof jsonb,operation text) returns void language plpgsql volatile security definer set search_path=pg_catalog set row_security=on as $$begin return; end$$',
        'create or replace function openpc.begin_runtime_target_activation_confirmation(proof_wire bytea,nonce bytea,mac bytea) returns table(binding jsonb,admission_digest text) language plpgsql volatile security definer set search_path=pg_catalog set row_security=on as $$begin return; end$$',
        'alter table control.runtime_target_disposition_admission no force row level security',
        'alter table control.runtime_target_disposition_delivery disable trigger runtime_target_disposition_immutable',
        'alter table control.runtime_target_disposition_admission disable trigger artifact_lifecycle_fence',
        'grant insert on control.runtime_target_disposition_acknowledgement to openpc_control_worker',
        'grant update(claims) on control.runtime_target_disposition_delivery to openpc_control_worker',
        'grant select(verifier_secret) on control.runtime_target_disposition_key to openpc_control_worker',
        'create or replace function openpc.lock_runtime_target_restore_sources(target uuid,expected_source jsonb,proof jsonb) returns void language plpgsql volatile security definer set search_path=pg_catalog set row_security=on as $$begin return; end$$',
        'create or replace function openpc.begin_runtime_target_unstarted_restore(proof_wire bytea,nonce bytea,mac bytea) returns table(binding jsonb,admission_digest text) language plpgsql volatile security definer set search_path=pg_catalog set row_security=on as $$begin return; end$$',
        'create or replace function openpc.commit_runtime_target_disposition(kind text,wire bytea,nonce bytea,mac bytea) returns boolean language plpgsql volatile security definer set search_path=pg_catalog set row_security=on as $$begin return true; end$$',
      ];
      for (const defect of defects) {
        await owner.query('begin');
        await owner.query(defect);
        await expect(
          owner.query('select openpc.assert_runtime_target_disposition_owner()'),
        ).rejects.toMatchObject({ code: 'P0001', message: 'TARGET-DISPOSITION-OWNER-UNAVAILABLE' });
        await owner.query('rollback');
      }
      await client.query('select openpc.assert_runtime_target_disposition_owner()');
      for (const table of tables) {
        expect(
          (await owner.query(`select count(*)::integer count from ${table}`)).rows[0]?.count,
        ).toBe(0);
      }
    } finally {
      await client.query('rollback');
      await owner.query('rollback');
      client.release();
      owner.release();
      await Promise.all([worker.end(), admin.end()]);
    }
  },
);

// Initial trust rows only. Exercise the actual conflicting SQL lock schedule;
// this component is not module enablement or target publication acceptance.
integration(
  'Fact custody fails fast against Participant-first module contention',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const contender = await admin.connect(),
      observer = await admin.connect(),
      native = await worker.connect();
    const participant = id(),
      privacy = id();
    let pending: Promise<unknown> | undefined;
    const begin = async () => {
      await native.query('begin');
      await native.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',true)",
        [participant, privacy, id()],
      );
    };
    try {
      await observer.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Target Fact lock initial trust','ACTIVE',1)",
        [participant],
      );
      await observer.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Target Fact locks','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [privacy, participant],
      );
      await contender.query('begin');
      await contender.query("set local statement_timeout='5s'");
      await contender.query(
        'select participant_id from control.participant where participant_id=$1 for share',
        [participant],
      );
      await begin();
      const moduleKey = `module-admission:${participant}:${privacy}`;
      await native.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
        moduleKey,
      ]);
      const contenderPid = (await contender.query('select pg_backend_pid() pid')).rows[0].pid;
      pending = contender.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
        moduleKey,
      ]);
      let blocked = false;
      for (let attempt = 0; attempt < 100; attempt++) {
        blocked =
          (
            await observer.query(
              "select wait_event_type='Lock' blocked from pg_stat_activity where pid=$1",
              [contenderPid],
            )
          ).rows[0]?.blocked === true;
        if (blocked) break;
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      expect(blocked).toBe(true);
      await expect(
        native.query('select openpc.lock_fact_workload_context(true)'),
      ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
      await native.query('rollback');
      await pending;
      pending = undefined;
      await contender.query('rollback');
      // The second row lock also must not wait; failure cannot become readiness.
      await contender.query('begin');
      await contender.query(
        'select privacy_domain_id from control.privacy_domain where privacy_domain_id=$1 for update',
        [privacy],
      );
      await begin();
      await expect(
        native.query('select openpc.lock_fact_workload_context(true)'),
      ).rejects.toMatchObject({ code: 'P0001', message: 'PC-DATA-6007' });
      await native.query('rollback');
      await contender.query('rollback');
      await begin();
      await native.query('select openpc.lock_fact_workload_context(true)');
      await native.query('select openpc.lock_fact_workload_context()');
      await native.query('rollback');
      await begin();
      await expect(
        native.query('select openpc.lock_fact_workload_context(null::boolean)'),
      ).rejects.toMatchObject({ code: 'P0001', message: 'PC-AUTH-0005-FACT-SOURCE' });
      await native.query('rollback');
    } finally {
      await native.query('rollback');
      await pending?.catch(() => undefined);
      await contender.query('rollback');
      native.release();
      contender.release();
      observer.release();
      await Promise.all([worker.end(), admin.end()]);
    }
  },
  20000,
);

// Installed SQL and actual worker authentication only. No activation, rotation,
// approval or ACK is seeded; positive credential continuity is a separate test.
integration(
  'keeps credential denial handover closed and compiles ordinary rotation history against the real schema',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const owner = await admin.connect(),
      native = await worker.connect();
    try {
      const expected = new Map([
        ['expired_denial_credential_provenance', true],
        ['expired_denial_credential_bootstrap', true],
        ['expired_credential_denial_state_digest', false],
        ['begin_expired_credential_denial_handover', true],
        ['expired_credential_handover_issuance_matches', false],
      ]);
      const installed = await owner.query<{
        name: string;
        owner: string;
        definer: boolean;
        volatility: string;
        public_execute: boolean;
      }>(
        `select p.proname name,p.proowner::regrole::text owner,p.prosecdef definer,p.provolatile volatility,
         exists(select 1 from aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
          where a.grantee=0 and a.privilege_type='EXECUTE') public_execute
         from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='openpc' and p.proname=any($1::text[])`,
        [[...expected.keys()]],
      );
      expect(installed.rowCount).toBe(expected.size);
      for (const row of installed.rows) {
        expect(row).toMatchObject({
          owner: 'openpc_control_owner',
          definer: expected.get(row.name),
          volatility: 'v',
          public_execute: false,
        });
      }
      // Compile the installed ordinary-rotation joins in the real forced-RLS
      // owner context, even without a rotated credential in this empty fixture.
      const definition = (
        await owner.query<{ body: string }>(
          "select pg_get_functiondef('openpc.expired_denial_credential_provenance(uuid,text,uuid)'::regprocedure) body",
        )
      ).rows[0]!.body;
      const declarations = /DECLARE[\s\S]*?\nBEGIN/u.exec(definition)?.[0];
      const rotation = /SELECT array_agg\(chosen_rotation[\s\S]*?(?=\n IF cardinality)/u.exec(
        definition,
      )?.[0];
      expect(declarations).toBeDefined();
      expect(rotation).toBeDefined();
      await context(owner);
      await owner.query('set local role openpc_control_owner');
      await owner.query(`do $ordinary_rotation_lookup$ DECLARE wanted_rotation uuid;
        ${declarations!.slice('DECLARE'.length)} ${rotation} END $ordinary_rotation_lookup$;`);
      await owner.query('rollback');
      const key = (
        await owner.query<{ verifier_secret: Buffer }>(
          "select verifier_secret from control.runtime_target_disposition_key where database_role='openpc_local_control_worker'",
        )
      ).rows[0]!.verifier_secret;
      const nonce = randomBytes(32),
        wire = Buffer.from('{"version":2}');
      for (const domain of [
        'OPENPC_EXPIRED_ACTIVATION_DENIAL_V1',
        'OPENPC_EXPIRED_UNSIGNED_DENIAL_HANDOVER_V1',
        'OPENPC_EXPIRED_CREDENTIAL_DENIAL_HANDOVER_REQUEST_V1',
        'OPENPC_EXPIRED_CREDENTIAL_DENIAL_HANDOVER_V1',
      ]) {
        const mac = createHmac('sha256', key)
          .update(domain)
          .update(createHash('sha256').update(wire).digest())
          .update(nonce)
          .digest();
        await context(native);
        await expect(
          native.query('select * from openpc.begin_expired_credential_denial_handover($1,$2,$3)', [
            wire,
            nonce,
            mac,
          ]),
        ).rejects.toMatchObject({
          code: 'P0001',
          message:
            domain === 'OPENPC_EXPIRED_CREDENTIAL_DENIAL_HANDOVER_V1'
              ? 'EXPIRED-CREDENTIAL-DENIAL-PROOF'
              : 'PC-AUTH-0005',
        });
        await native.query('rollback');
      }
      await context(native);
      expect(
        (
          await native.query(
            'select openpc.expired_credential_handover_issuance_matches($1,4,$2,$3) admitted',
            [id(), `sha256:${'a1'.repeat(32)}`, 'untrusted-worker'],
          )
        ).rows[0],
      ).toEqual({ admitted: false });
      await native.query('rollback');
      for (const table of [
        'runtime_expired_activation_denial',
        'runtime_expired_denial_handover',
        'runtime_denied_predecessor',
      ]) {
        await context(native);
        await expect(
          native.query(`insert into control.${table} default values`),
        ).rejects.toMatchObject(
          table === 'runtime_denied_predecessor'
            ? { code: 'P0001', message: 'DENIED-PREDECESSOR-ORIGINAL' }
            : { code: '42501' },
        );
        await native.query('rollback');
        await expect(native.query(`truncate control.${table}`)).rejects.toMatchObject({
          code: '42501',
        });
        expect(
          (await owner.query(`select count(*)::integer count from control.${table}`)).rows[0],
        ).toEqual({ count: 0 });
      }
    } finally {
      await native.query('rollback');
      await owner.query('rollback');
      native.release();
      owner.release();
      await Promise.all([worker.end(), admin.end()]);
    }
  },
  20000,
);

// Real PostgreSQL lock scheduling and actual non-bypass read role only. Missing
// actor authority is intentional: no metadata callback may become a grant.
integration(
  'queues current runtime reads before authority and preserves tighter caller timeouts under real contention',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    let producer: PoolClient | undefined,
      observer: PoolClient | undefined,
      reader: Pool | undefined;
    let pending:
      | Promise<{ kind: 'returned'; value: string } | { kind: 'rejected'; error: unknown }>
      | undefined;
    let failure: { error: unknown } | undefined;
    try {
      producer = await admin.connect();
      observer = await admin.connect();
      const participant = id(),
        privacy = id(),
        target = id();
      await observer.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch)values($1,'Runtime admission queue initial trust','ACTIVE',1)",
        [participant],
      );
      await observer.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)values($1,$2,'Runtime queue','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [privacy, participant],
      );
      const ctx: ReadContext = {
        resourceType: 'runtime-targets',
        resourceId: target,
        actionIntentId: 'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1',
        authorization: {
          participantId: participant.toUpperCase(),
          privacyDomainId: privacy,
          principalId: id(),
          sessionId: id(),
          sessionEpoch: '1',
          participantEpoch: '1',
          principalEpoch: '1',
          assignmentId: id(),
          assignmentEpoch: '1',
          authorityEnvelopeId: id(),
          authorityEpoch: '1',
          delegationEpoch: '1',
        },
      };
      const producerPid = (await producer.query<{ pid: number }>('select pg_backend_pid() pid'))
        .rows[0]!.pid;
      for (const timeout of [5000, 100]) {
        const label = 'runtime-queue-' + id();
        const url = new URL(process.env.OPENPC_I02_RUNTIME_DATABASE_URL!);
        url.username = 'openpc_configuration_runtime';
        url.searchParams.set('application_name', label);
        url.searchParams.set('options', `-c lock_timeout=${timeout}`);
        reader = new Pool({ connectionString: url.href, max: 1 });
        expect(
          (
            await reader.query<{ role: string; superuser: boolean; bypass: boolean }>(
              'select current_user::text role,rolsuper superuser,rolbypassrls bypass from pg_roles where rolname=current_user',
            )
          ).rows,
        ).toEqual([{ role: 'openpc_configuration_runtime', superuser: false, bypass: false }]);
        await producer.query('begin');
        await producer.query(
          "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||$1::text,0))",
          [participant],
        );
        let calls = 0;
        pending = new ScopedConfigurationRead(reader)
          .executeCurrent(ctx, async () => {
            calls++;
            return 'forbidden source';
          })
          .then(
            (value) => ({ kind: 'returned' as const, value }),
            (error) => ({ kind: 'rejected' as const, error }),
          );
        let readerPid: number | undefined;
        if (timeout === 5000) {
          const deadline = Date.now() + 2500;
          while (Date.now() < deadline) {
            const blocked = (
              await observer.query<{ pid: number }>(
                "select pid from pg_stat_activity where application_name=$1 and wait_event_type='Lock' and $2::integer=any(pg_blocking_pids(pid))",
                [label, producerPid],
              )
            ).rows;
            if (blocked.length === 1) {
              readerPid = blocked[0]!.pid;
              break;
            }
            await new Promise((resolve) => setTimeout(resolve, 5));
          }
          expect(readerPid).toBeDefined();
          expect(calls).toBe(0);
          await producer.query('commit');
          expect(await pending).toMatchObject({
            kind: 'rejected',
            error: { code: 'PC-AUTH-0005' },
          });
          expect(
            (
              await observer.query<{ count: number }>(
                "select count(*)::integer count from pg_locks where pid=$1 and locktype='advisory'",
                [readerPid],
              )
            ).rows,
          ).toEqual([{ count: 0 }]);
        } else {
          expect(await pending).toMatchObject({
            kind: 'rejected',
            error: { code: 'PC-DATA-6007' },
          });
          await producer.query('rollback');
        }
        expect(calls).toBe(0);
        pending = undefined;
        expect((await reader.query<{ lock_timeout: string }>('show lock_timeout')).rows[0]).toEqual(
          { lock_timeout: timeout === 5000 ? '5s' : '100ms' },
        );
        await reader.end();
        reader = undefined;
      }
    } catch (error) {
      failure = { error };
    }
    await closeFixtureResources(
      [
        async () => {
          if (producer) await producer.query('rollback');
        },
        async () => {
          if (pending) await pending;
        },
        () => {
          producer?.release();
          observer?.release();
        },
        () => reader?.end(),
        () => admin.end(),
      ],
      failure,
    );
    if (failure) throw failure.error;
  },
  20000,
);
