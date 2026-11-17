import { Pool, type PoolClient } from 'pg';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  retirementWireBytes,
  type StoreRetirementHost,
} from '../../../services/control-api/src/evidence/store-retirement-wire.js';
import { installStoreRetirementHost } from '../../../services/control-api/src/evidence/store-retirement-installation.js';
import { PostgresStoreRetirementWorkerStore } from '../../../services/control-api/src/evidence/store-retirement-worker-store.js';
import { retirementWireFixture } from '../../../services/control-api/src/evidence/store-retirement-wire-fixture.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { digest } from './public-governance-client.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && runtimeUrl && workerUrl ? it : it.skip;
const admission = 'ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1';
const reconcile = 'ACT-EVIDENCE_DELETIONS_RECONCILE_STORE_BATCH-V1';

// Migration/denial preflight only. No fabricated admission, native source,
// approval, signed outcome or physical-effect acceptance is created here.
integration(
  'installs scoped store-retirement owners and rejects authority-free source, delivery and outcome calls',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const participant = id(),
      privacy = id();
    async function transaction(
      pool: Pool,
      action: string,
      work: (client: PoolClient) => Promise<void>,
    ) {
      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          participant,
          privacy,
          id(),
          action,
        ]);
        await work(client);
      } finally {
        await client.query('rollback');
        client.release();
      }
    }
    try {
      // Initial installed host/workload trust only. Business authority is never seeded.
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Retirement host test','ACTIVE',1)",
        [participant],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Retirement','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [privacy, participant],
      );
      await admin.query(
        'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
        [participant, privacy],
      );
      const principal = id(),
        credential = id();
      const key = () =>
        generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
          type: 'spki',
          format: 'der',
        });
      const workloadKey = key(),
        controlKey = key(),
        targetKey = key(),
        secret = randomBytes(32);
      const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest();
      await admin.query(
        "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Retirement worker','ACTIVE',1)",
        [principal, participant],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from,valid_until,secret_fingerprint)
        values($1::uuid,$2,$3,'WORKLOAD_MTLS','urn:openpc:retirement-test-ca',$1::uuid::text,'retirement-test',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',$4)`,
        [credential, participant, principal, sha(workloadKey), workloadKey],
      );
      const host: StoreRetirementHost = {
        environment_id: 'postgres-test',
        target_id: 'facts',
        scope: { participant_id: participant, privacy_domain_id: privacy },
        store: 'openpc_facts',
      };
      const hostWire = retirementWireBytes(host),
        hostDigest = sha(hostWire).toString('hex');
      const installation = {
        host,
        controlSpki: controlKey,
        targetSpki: targetKey,
        verifierSecret: secret,
        databaseRole: new URL(workerUrl!).username,
        workloadCredentialId: credential,
        workloadCredentialEpoch: '1',
        validFromMs: Date.now() - 30000,
        validUntilMs: Date.now() + 3500000,
        installationReference: 'Initial scoped host test trust',
      };
      await admin.query(`create function openpc.test_retirement_installation_loss() returns trigger language plpgsql as $$
        begin raise exception 'TEST_RETIREMENT_INSTALLATION_LOSS'; end $$;
        create trigger test_retirement_installation_loss before insert on control.store_retirement_verifier_key
        for each row execute function openpc.test_retirement_installation_loss()`);
      try {
        await expect(installStoreRetirementHost(admin, installation)).rejects.toThrow(
          'installation rejected',
        );
        expect(
          (await admin.query('select count(*)::int n from control.store_retirement_host')).rows,
        ).toEqual([{ n: 0 }]);
        expect(
          (await admin.query('select count(*)::int n from control.store_retirement_verifier_key'))
            .rows,
        ).toEqual([{ n: 0 }]);
      } finally {
        await admin.query(
          'drop trigger test_retirement_installation_loss on control.store_retirement_verifier_key; drop function openpc.test_retirement_installation_loss()',
        );
      }
      const concurrent = await Promise.all([
        installStoreRetirementHost(admin, installation),
        installStoreRetirementHost(admin, installation),
      ]);
      expect(concurrent.map((result) => result.state).sort()).toEqual(['INSTALLED', 'REUSED']);
      expect(concurrent.every((result) => result.hostDigest === hostDigest)).toBe(true);
      for (const changed of [
        { verifierSecret: randomBytes(32) },
        { controlSpki: key() },
        { targetSpki: key() },
        { workloadCredentialEpoch: '2' },
        { databaseRole: new URL(runtimeUrl!).username },
        { validUntilMs: installation.validUntilMs + 1 },
        { validFromMs: installation.validFromMs - 1 },
        { installationReference: 'Changed installation' },
        { host: { ...host, scope: { ...host.scope, privacy_domain_id: id() } } },
        { controlSpki: workloadKey },
        { targetSpki: workloadKey },
      ])
        await expect(
          installStoreRetirementHost(admin, { ...installation, ...changed }),
        ).rejects.toThrow('installation rejected');
      for (const pool of [runtime, worker])
        await expect(installStoreRetirementHost(pool, installation)).rejects.toThrow(
          'installation rejected',
        );
      // A new connection must read the exact originally committed installation.
      const restart = new Pool({ connectionString: adminUrl, max: 1 });
      try {
        expect(await installStoreRetirementHost(restart, installation)).toEqual({
          hostDigest,
          state: 'REUSED',
        });
      } finally {
        await restart.end();
      }
      expect(secret.some((byte) => byte !== 0)).toBe(true);
      await transaction(worker, reconcile, async (client) => {
        await client.query('select openpc.lock_store_retirement_workload($1)', [hostDigest]);
        const installed = await client.query(
          'select host_digest from control.store_retirement_host',
        );
        expect(installed.rows).toEqual([{ host_digest: hostDigest }]);
      });
      await transaction(worker, admission, async (client) => {
        await expect(
          client.query('select openpc.lock_store_retirement_workload($1)', [hostDigest]),
        ).rejects.toThrow('PC-AUTH-0005');
      });
      await transaction(worker, reconcile, async (client) => {
        await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          id(),
          id(),
          id(),
          reconcile,
        ]);
        expect(
          (await client.query('select host_digest from control.store_retirement_host')).rows,
        ).toEqual([]);
        await expect(
          client.query('select openpc.lock_store_retirement_workload($1)', [hostDigest]),
        ).rejects.toMatchObject({ code: 'P0002' });
      });
      const store = new PostgresStoreRetirementWorkerStore(worker, host, secret);
      try {
        const absent = id();
        await expect(store.pendingAttempts()).resolves.toEqual([]);
        await expect(store.readAttempt(absent)).rejects.toThrow(
          'Committed retirement admission unavailable',
        );
        await expect(store.prepareRequest(absent)).rejects.toThrow(
          'Committed retirement admission unavailable',
        );
        await expect(store.needsCancellation(absent)).rejects.toThrow(
          'Committed retirement admission unavailable',
        );
        let called = false;
        await expect(
          store.dispatchDelivery(absent, id(), async () => {
            called = true;
          }),
        ).rejects.toThrow('Committed retirement admission unavailable');
        expect(called).toBe(false);
        await expect(store.readOutcome(absent)).rejects.toThrow(
          'Committed retirement admission unavailable',
        );
        await expect(store.commitCancellation(absent)).rejects.toThrow(
          'Committed retirement admission unavailable',
        );
        await expect(store.recordDelivery(absent, 'REQUEST', Buffer.from('{}'))).rejects.toThrow(
          'Committed retirement admission unavailable',
        );
        await expect(store.recordOutcome(absent, Buffer.from('{}'))).rejects.toThrow(
          'Committed retirement admission unavailable',
        );
      } finally {
        store.close();
        secret.fill(0);
      }
      const tables =
        await admin.query(`select relname,relrowsecurity,relforcerowsecurity from pg_class
      where relnamespace='control'::regnamespace and relname like 'store_retirement_%' and relkind='r' order by relname`);
      expect(tables.rows).toHaveLength(6);
      for (const row of tables.rows)
        expect(row).toMatchObject({ relrowsecurity: true, relforcerowsecurity: true });
      for (const role of [
        'openpc_control_runtime',
        'openpc_control_worker',
        'openpc_control_reader',
      ]) {
        const grants = await admin.query(
          `select
       has_table_privilege($1,'control.store_retirement_verifier_key','SELECT') secret,
       has_table_privilege($1,'control.store_retirement_host','INSERT') install,
       has_table_privilege($1,'control.store_retirement_admission','INSERT') admit,
       has_table_privilege($1,'control.store_retirement_delivery','INSERT') dispatch,
       has_table_privilege($1,'control.store_retirement_outcome','INSERT') outcome,
       has_table_privilege($1,'control.store_retirement_admission','UPDATE,DELETE') rewrite`,
          [role],
        );
        expect(grants.rows[0]).toEqual({
          secret: false,
          install: false,
          admit: role === 'openpc_control_runtime',
          dispatch: role === 'openpc_control_worker',
          outcome: role === 'openpc_control_worker',
          rewrite: false,
        });
      }
      const actions = await admin.query(
        'select action_intent_id,maker_checker_required,step_up_required from control.action_intent where action_intent_id=any($1) order by action_intent_id',
        [[admission, reconcile]],
      );
      expect(actions.rows).toEqual([
        { action_intent_id: admission, maker_checker_required: true, step_up_required: true },
        { action_intent_id: reconcile, maker_checker_required: false, step_up_required: false },
      ]);
      const deferred = await admin.query(
        "select tgdeferrable,tginitdeferred from pg_trigger where tgrelid='control.store_retirement_admission'::regclass and tgname='store_retirement_command_required'",
      );
      expect(deferred.rows).toEqual([{ tgdeferrable: true, tginitdeferred: true }]);
      for (const pool of [runtime, worker]) {
        await transaction(pool, pool === runtime ? admission : reconcile, async (client) => {
          await expect(
            client.query('select * from control.store_retirement_verifier_key'),
          ).rejects.toMatchObject({ code: '42501' });
        });
        await transaction(pool, pool === runtime ? admission : reconcile, async (client) => {
          await expect(
            client.query('select openpc.store_retirement_source_binding($1,$2,$3)', [
              id(),
              Buffer.from('{"class":"CANDIDATE_PROJECTION","rows":[]}'),
              '[]',
            ]),
          ).rejects.toThrow('PC-DATA-6007');
        });
        await transaction(pool, pool === runtime ? admission : reconcile, async (client) => {
          await expect(
            client.query('select openpc.verify_store_retirement_commit($1,$2,$3,$4,$5,$6,$7)', [
              participant,
              privacy,
              'a'.repeat(64),
              'SOURCE',
              Buffer.alloc(32),
              Buffer.alloc(32),
              Buffer.alloc(32),
            ]),
          ).rejects.toThrow();
        });
      }
      await transaction(worker, reconcile, async (client) => {
        await expect(
          client.query('select openpc.lock_store_retirement_authority($1)', [id()]),
        ).rejects.toMatchObject({ code: 'P0002' });
      });
      const counts =
        await admin.query(`select (select count(*) from control.store_retirement_admission)::int admissions,
      (select count(*) from control.store_retirement_delivery)::int deliveries,
      (select count(*) from control.store_retirement_outcome)::int outcomes`);
      expect(counts.rows).toEqual([{ admissions: 0, deliveries: 0, outcomes: 0 }]);
      await admin.query(
        "update control.credential set state='REVOKED' where participant_id=$1 and credential_id=$2",
        [participant, credential],
      );
      await expect(installStoreRetirementHost(admin, installation)).rejects.toThrow(
        'installation rejected',
      );
      await transaction(worker, reconcile, async (client) => {
        await expect(
          client.query('select openpc.lock_store_retirement_workload($1)', [hostDigest]),
        ).rejects.toThrow('PC-AUTH-0005');
      });
      const preserved = await admin.query(
        'select host_wire,control_spki,target_spki,valid_until_ms::text from control.store_retirement_host where host_digest=$1',
        [hostDigest],
      );
      expect(preserved.rows).toEqual([
        {
          host_wire: hostWire,
          control_spki: controlKey,
          target_spki: targetKey,
          valid_until_ms: String(installation.validUntilMs),
        },
      ]);
    } finally {
      await Promise.all([admin.end(), runtime.end(), worker.end()]);
    }
  },
  120000,
);

// Proposal/recovery authority only: the synthetic selection has no installed
// native host. The real retained candidate journey separately proves execution.
integration(
  'recovers only an unadmitted native retirement with fresh independent approval and unchanged intent',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
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
      const evidenceId = id(),
        { attempt } = retirementWireFixture();
      const manifest = [
        {
          candidateId: 'candidate',
          evidenceId,
          streamId: 'original-source',
          recordId: 'original-record',
          sequence: '1',
          recordDigest: 'sha256:' + 'a'.repeat(64),
          segmentId: id(),
          objectDigest: 'sha256:' + 'b'.repeat(64),
        },
      ];
      const acknowledgements = [
        {
          candidateId: 'candidate',
          sinkReceipts: [
            {
              sinkId: 'original-sink',
              checkpointDigest: 'sha256:' + 'c'.repeat(64),
              receiptDigest: 'sha256:' + 'd'.repeat(64),
              acknowledgedAtMicros: '1800000000000000',
            },
          ],
        },
      ];
      const prepared = await fixture.prepareMutation(
        'evidence-deletions/store-retirements',
        admission,
        {
          participantId: `urn:openpc:participant:${participantId}`,
          hostDigest: 'a'.repeat(64),
          retentionPolicyId: `urn:openpc:resource:${id()}`,
          previousAttemptId: null,
          sourceBinding: {
            version: 'OPENPC_STORE_RETIREMENT_SOURCE_V1',
            selectionWireHex: retirementWireBytes(attempt.selection).toString('hex'),
            recordRefs: [{ candidateId: 'candidate', evidenceId }],
            manifest,
            acknowledgements,
            archiveManifestDigest: digest(manifest).slice(7),
            archiveAcknowledgementDigest: digest(acknowledgements).slice(7),
            retentionNotBeforeMs: '1800000000000',
            lifecycleRevision: '9',
          },
        },
        true,
      );
      const { client, policyUrl, maker, checker } = fixture.governance;
      const read = async (approvalId: string) => {
        const result = await fixture!.approvalRead(approvalId);
        expect(result.status).toBe(200);
        return result.body;
      };
      const original = await read(prepared.approvalId);
      const action = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
      const resume = async (view: typeof original, key: string, actor = maker) =>
        client.request(
          `${policyUrl}/api/v1/approval-requests/urn:openpc:resource:${prepared.approvalId}`,
          actor,
          {
            command: 'RESUME',
            actionIntentId: action,
            actionIntentDigest: client.actionDigests.get(action),
            expectedRevision: '2',
            predecessorCandidateId: view.attemptId,
            expectedAttempt: view.attempt,
            candidateDigest: view.candidateDigest,
            reason: 'Recover the original unadmitted native retirement.',
          },
          {
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
            'X-Request-ID': id(),
            'X-Correlation-ID': id(),
            'Idempotency-Key': key,
            'X-CSRF-Token': await client.csrf(actor, action, policyUrl),
            'X-OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
            'If-Match': `"${digest({ resourceId: prepared.approvalId, revision: '2' })}"`,
          },
          'PATCH',
        );
      expect(original).toMatchObject({
        state: 'APPROVED',
        approvalUsable: true,
        canRequestResume: false,
        operationRef: null,
      });
      expect([403, 409]).toContain((await resume(original, `live-${id()}`)).status);
      const expiry = Number(
        (
          await admin.query(
            `select max(extract(epoch from least(m.expires_at,m.consumed_at+interval '5 minutes'))*1000) expiry from control.approval_decision_record d join control.mfa_challenge m using(participant_id,mfa_challenge_id) where d.approval_request_id=$1`,
            [prepared.approvalId],
          )
        ).rows[0].expiry,
      );
      expect(expiry).toBeGreaterThan(Date.now());
      while (Date.now() <= expiry) {
        process.stdout.write(
          `OPENPC_RETIREMENT_RESUME|natural-expiry|remaining_ms=${Math.ceil(expiry - Date.now())}\n`,
        );
        await delay(Math.min(30000, expiry - Date.now() + 100));
      }
      expect(await read(prepared.approvalId)).toMatchObject({
        canRequestResume: true,
        approvalUsable: false,
        operationRef: null,
      });
      expect([403, 404]).toContain((await resume(original, `checker-${id()}`, checker)).status);
      expect([403, 404, 422]).toContain(
        (await resume({ ...original, candidateDigest: digest({}) }, `changed-${id()}`)).status,
      );
      const keys = [`resume-${id()}`, `resume-${id()}`];
      const raced = await Promise.all(keys.map((key) => resume(original, key)));
      const winner = raced.findIndex((value) => value.status === 202);
      expect(winner, JSON.stringify(raced)).toBeGreaterThanOrEqual(0);
      expect(raced.filter((value) => value.status === 202)).toHaveLength(1);
      expect([403, 409]).toContain(raced[1 - winner]!.status);
      expect(await resume(original, keys[winner]!)).toEqual(raced[winner]);
      const successor = String(raced[winner]!.body.resourceRef).slice(-36);
      expect(await read(successor)).toMatchObject({
        attempt: '2',
        state: 'APPROVAL_REQUESTED',
        candidate: original.candidate,
        candidateDigest: original.candidateDigest,
        resourceRef: original.resourceRef,
        businessIdempotencyKey: original.businessIdempotencyKey,
        predecessorApprovalRef: `urn:openpc:resource:${prepared.approvalId}`,
        operationRef: null,
      });
      expect((await prepared.commit()).status).toBe(403);
      const approve = 'ACT-POLICY_APPROVE_REQUEST-V1',
        targetRef = `urn:openpc:resource:${successor}`;
      const inputDigest = digest({
        actionIntentId: approve,
        approvalRequestId: targetRef,
        candidateDigest: original.candidateDigest,
        expectedRevision: '1',
        decision: 'APPROVE',
      });
      await client.stepUp(checker, approve, successor, inputDigest);
      expect(
        (
          await client.policyMutation(
            checker,
            `/api/v1/approval-requests/${targetRef}/approve`,
            {
              targetRef,
              actionIntentId: approve,
              actionIntentDigest: client.actionDigests.get(approve),
              inputDigest,
              expectedRevision: '1',
              reason: 'Independently approve the same native retirement intent.',
            },
            '1',
          )
        ).status,
      ).toBe(202);
      expect(await read(successor)).toMatchObject({
        state: 'APPROVED',
        approvalUsable: true,
        canRequestResume: false,
        operationRef: null,
      });
      await prepared.stepUp();
      // Fresh approval does not fabricate installed authority, source readiness or
      // physical success. Actual admission remains independently closed.
      expect((await prepared.commit()).status).toBe(412);
      for (const [table, identity] of [
        ['store_retirement_admission', 'attempt_id'],
        ['store_retirement_delivery', 'attempt_id'],
        ['store_retirement_outcome', 'attempt_id'],
        ['configuration_work', 'resource_id'],
        ['mutation_evidence', 'aggregate_id'],
        ['audit_occurrence', 'aggregate_id'],
      ])
        expect(
          (
            await admin.query(
              `select count(*)::int count from control.${table} where participant_id=$1 and privacy_domain_id=$2 and ${identity}=$3`,
              [participantId, privacyDomainId, prepared.resourceId],
            )
          ).rows[0].count,
          `The original retirement must have no ${table} effect`,
        ).toBe(0);
    } finally {
      await fixture?.close();
      await admin.end();
    }
  },
  360000,
);
