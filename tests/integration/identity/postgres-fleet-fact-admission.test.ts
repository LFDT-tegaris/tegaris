import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { installInitialFleetFailureSigner } from '../local-runtime/fact-failure-bootstrap.js';
import { verifyFleetFailureCustody } from './fleet-failure-custody.js';
import {
  encodeFactConsumerFailure,
  factConsumerFailureWorkItem,
  type FactConsumerFailure,
} from '../../../packages/security-kernel/src/fact-consumer/failure.js';
import {
  signFactConsumerFailure,
  verifyFactConsumerFailureSignature,
} from '../../../packages/security-kernel/src/fact-consumer/failure-cose.js';
import { createHash, createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { installInitialFleetConsumerProfile } from '../local-runtime/fact-consumer-bootstrap.js';
import {
  encodeFactConsumerProfile,
  evidenceKeyId,
  factConsumerProfileDigest,
  signFactConsumerProfile,
  type FactConsumerProfile,
  type InstalledFactConsumerProfile,
} from '../../../packages/security-kernel/src/index.js';
import { installFactConsumerProfile } from '../../../services/control-api/src/fact-consumers/profile-store.js';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;

// SQL capability/ordering acceptance only. Synthetic metadata here cannot
// establish native Fact authentication or Fleet runtime consumption.
integration(
  'Fleet admits only exact native capabilities, commits cursor and effect atomically, and preserves scoped replay',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const participant = id(),
      privacy = id(),
      otherPrivacy = id();
    const secret = randomBytes(32);
    const candidate = id();
    const hash = `sha256:${'ab'.repeat(32)}`;
    const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const issuerSpki = issuer.publicKey.export({ format: 'der', type: 'spki' });
    const issuerPrivate = issuer.privateKey.export({ format: 'der', type: 'pkcs8' });
    const workload = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const workloadSpki = workload.publicKey.export({ format: 'der', type: 'spki' });
    const workloadPrincipal = id(),
      workloadCredential = id();
    const profile: FactConsumerProfile = {
      environmentId: 'fleet-admission-test',
      participantId: participant,
      privacyDomainId: privacy,
      profileId: 'fact-admission',
      revision: '1',
      consumerId: 'LS-FLEET-CONTROL',
      subscriptionId: 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1',
      validFromMs: Date.now() - 60000,
      validUntilMs: Date.now() + 3600000,
      issuerKeyId: evidenceKeyId(issuerSpki),
      workloadCredentialId: workloadCredential,
      workloadCredentialEpoch: '1',
      databaseRole: 'openpc_local_control_worker',
      maximumAttempts: 3,
      initialBackoffMs: 100,
      maximumBackoffMs: 1000,
    };
    const payload = encodeFactConsumerProfile(profile),
      cose = signFactConsumerProfile(issuerPrivate, issuerSpki, payload);
    let profileDigest = factConsumerProfileDigest(cose);
    const installed: InstalledFactConsumerProfile = {
      ...profile,
      issuerSpkiDer: issuerSpki,
      signedProfileDigest: profileDigest,
    };
    const nativeAdmission = (scope: string, digest: string, blocked: boolean) => {
      expect(process.env.OPENPC_FACT_WORKLOAD_TEST_BINARY).toBeTruthy();
      const output = execFileSync(
        process.env.OPENPC_FACT_WORKLOAD_TEST_BINARY!,
        [
          'consumer_profile::tests::postgres_typescript_consumer_profile_native_admission',
          '--exact',
          '--ignored',
        ],
        {
          encoding: 'utf8',
          timeout: 10000,
          env: {
            ...process.env,
            OPENPC_FACT_CONSUMER_PARTICIPANT: participant,
            OPENPC_FACT_CONSUMER_PRIVACY: scope,
            OPENPC_FACT_CONSUMER_DIGEST: digest,
            OPENPC_FACT_CONSUMER_EXPECT_BLOCKED: blocked ? '1' : '0',
          },
        },
      );
      expect(output).toContain('1 passed; 0 failed');
    };
    const material = {
      consumerId: 'LS-FLEET-CONTROL',
      participantId: participant,
      privacyDomainId: privacy,
      candidateId: candidate,
      generationId: id(),
      factType: 'CONTRACT_STATE_CALL',
      sequence: '1',
      factDigest: hash,
      signedFactDigest: hash,
      envelope: {
        id: id(),
        subject: `urn:openpc:resource:${candidate}`,
        sequence: '1',
        participantid: `urn:openpc:participant:${participant}`,
        privacydomainid: `urn:openpc:privacy-domain:${privacy}`,
        source: 'urn:openpc:service:LS-FACT-BRIDGE',
        type: 'io.openpc.fact.candidate.admitted.v1',
        datadigest: hash,
      },
    };
    const currentLease = id();
    const capability = (value: unknown, domain = 'OPENPC_FLEET_FACT_ADMISSION_V2') => {
      const bytes = Buffer.from(canonicalJson(value));
      const nonce = randomBytes(32);
      if (domain === 'OPENPC_FLEET_FACT_ADMISSION_V2')
        Buffer.from(currentLease.replaceAll('-', ''), 'hex').copy(nonce);
      return [
        bytes,
        nonce,
        createHmac('sha256', secret)
          .update(domain)
          .update(
            domain === 'OPENPC_FLEET_FACT_ADMISSION_V1'
              ? Buffer.alloc(0)
              : Buffer.from(profileDigest.slice(7), 'hex'),
          )
          .update(createHash('sha256').update(bytes).digest())
          .update(nonce)
          .digest(),
      ];
    };
    const setContext = (client: PoolClient, scope = privacy) =>
      client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-OPERATIONS_READ_OPERATION-V1',true)",
        [participant, scope, id()],
      );
    const counts = async () =>
      (
        await admin.query(
          `select
    (select count(*)::int from control.fleet_fact_admission_inbox where participant_id=$1) n,
    (select max(sequence)::text from control.fleet_fact_admission_cursor where participant_id=$1) head`,
          [participant],
        )
      ).rows[0];
    const eventMaterial = (value: typeof material) => ({
      participantId: participant,
      privacyDomainId: privacy,
      candidateId: value.candidateId,
      generationId: value.generationId,
      factType: value.factType,
      sequence: value.sequence,
      consumerId: value.consumerId,
      eventId: value.envelope.id,
      envelope: value.envelope,
      envelopeDigest: `sha256:${createHash('sha256').update(canonicalJson(value.envelope)).digest('hex')}`,
      dataDigest: value.envelope.datadigest,
    });
    const delivery = async (begin: boolean, value: unknown) => {
      const client = await worker.connect();
      try {
        await client.query('begin');
        await setContext(client);
        const result = await client.query(
          begin
            ? 'select openpc.begin_fleet_fact_delivery($1,$2,$3,$4) result'
            : 'select openpc.fail_fleet_fact_delivery($1,$2,$3,$4) result',
          [
            ...capability(
              value,
              begin ? 'OPENPC_FLEET_FACT_DELIVERY_BEGIN_V1' : 'OPENPC_FLEET_FACT_DELIVERY_FAIL_V1',
            ),
            profileDigest,
          ],
        );
        await client.query('commit');
        return result.rows[0].result;
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
    };
    const beginDelivery = (value: typeof material, leaseId: string) =>
      delivery(true, { event: eventMaterial(value), leaseId });
    const failDelivery = (value: typeof material, leaseId: string, outcome = 'FAILED') =>
      delivery(false, {
        participantId: participant,
        privacyDomainId: privacy,
        eventId: value.envelope.id,
        leaseId,
        outcome,
        problem: 'PC-DATA-6005',
      });
    const waitDue = async (eventId: string) => {
      await admin.query(
        `select pg_sleep(greatest(0,next_attempt_ms/1000-extract(epoch from clock_timestamp())))
        from control.fleet_fact_delivery where participant_id=$1 and event_id=$2`,
        [participant, eventId],
      );
    };
    try {
      for (const role of [
        'openpc_control_runtime',
        'openpc_control_worker',
        'openpc_control_reader',
        'openpc_control_platform_runtime',
      ]) {
        for (const table of [
          'fleet_fact_admission_inbox',
          'fleet_fact_admission_cursor',
          'fleet_fact_delivery',
          'fleet_fact_delivery_attempt',
          'fleet_fact_quarantine',
          'fleet_fact_failure_outbox',
          'fact_consumer_failure_signer',
        ]) {
          for (const privilege of ['INSERT', 'UPDATE', 'DELETE']) {
            expect(
              (
                await admin.query('select has_table_privilege($1,$2,$3) allowed', [
                  role,
                  `control.${table}`,
                  privilege,
                ])
              ).rows[0].allowed,
              `${role}:${table}:${privilege}`,
            ).toBe(false);
          }
        }
        expect(
          (
            await admin.query(
              "select has_table_privilege($1,'control.fleet_fact_admission_key','SELECT') allowed",
              [role],
            )
          ).rows[0].allowed,
        ).toBe(false);
        for (const signature of [
          'openpc.commit_fleet_fact_admission(bytea,bytea,bytea)',
          'openpc.commit_fleet_fact_admission_v2(bytea,bytea,bytea,text)',
          'openpc.begin_fleet_fact_delivery(bytea,bytea,bytea,text)',
          'openpc.fail_fleet_fact_delivery(bytea,bytea,bytea,text)',
          'openpc.prepare_fleet_fact_quarantine(bytea,bytea,bytea,text)',
          'openpc.commit_fleet_fact_quarantine(bytea,bytea,bytea,text)',
        ])
          expect(
            (
              await admin.query("select has_function_privilege($1,$2,'EXECUTE') allowed", [
                role,
                signature,
              ])
            ).rows[0].allowed,
          ).toBe(role === 'openpc_control_worker');
      }
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Fleet test','ACTIVE',1)",
        [participant],
      );
      for (const scope of [privacy, otherPrivacy])
        await admin.query(
          "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,$1::uuid::text,'PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
          [scope, participant],
        );
      await admin.query(
        "insert into control.fleet_fact_admission_key(database_role,verifier_secret) values('openpc_local_control_worker',$1)",
        [secret],
      );
      await admin.query(
        "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Fleet consumer','ACTIVE',1)",
        [workloadPrincipal, participant],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
        public_key_digest,public_key_spki_der,state,credential_epoch,valid_from,valid_until,secret_fingerprint)
        values($1,$2,$3,'WORKLOAD_MTLS','urn:openpc:consumer-test-ca',$1::uuid::text,'consumer-test',$4,$5,'ACTIVE',1,
        clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',$4)`,
        [
          workloadCredential,
          participant,
          workloadPrincipal,
          createHash('sha256').update(workloadSpki).digest(),
          workloadSpki,
        ],
      );
      const installer = await admin.connect();
      try {
        await installFactConsumerProfile(
          installer,
          installed,
          payload,
          cose,
          'Initial Fleet consumer test trust',
        );
      } finally {
        installer.release();
      }
      nativeAdmission(privacy, profileDigest, false);
      const bootstrap = await admin.connect();
      let initialDigest: string;
      try {
        await bootstrap.query('begin');
        initialDigest = await installInitialFleetConsumerProfile(
          bootstrap,
          participant,
          otherPrivacy,
          workloadCredential,
        );
        expect(
          await installInitialFleetConsumerProfile(
            bootstrap,
            participant,
            otherPrivacy,
            workloadCredential,
          ),
        ).toBe(initialDigest);
        await bootstrap.query('commit');
      } finally {
        bootstrap.release();
      }
      nativeAdmission(otherPrivacy, initialDigest, false);
      for (const invalid of ['NULL_MAC', 'BAD_MAC', 'DOMAIN', 'SCOPE', 'GAP', 'EXTRA', 'PROFILE']) {
        const client = await worker.connect();
        try {
          await client.query('begin');
          await setContext(client, invalid === 'SCOPE' ? otherPrivacy : privacy);
          const params: (Buffer | null)[] = capability(
            invalid === 'EXTRA'
              ? { ...material, ready: true }
              : invalid === 'GAP'
                ? {
                    ...material,
                    sequence: '2',
                    envelope: { ...material.envelope, sequence: '2' },
                  }
                : material,
            invalid === 'DOMAIN' ? 'OTHER' : undefined,
          );
          if (invalid === 'NULL_MAC') params[2] = null;
          if (invalid === 'BAD_MAC') params[2] = Buffer.alloc(32);
          await expect(
            client.query('select openpc.commit_fleet_fact_admission_v2($1,$2,$3,$4)', [
              ...params,
              invalid === 'PROFILE' ? `sha256:${'cd'.repeat(32)}` : profileDigest,
            ]),
          ).rejects.toThrow();
        } finally {
          await client.query('rollback');
          client.release();
        }
        expect(await counts()).toEqual({ n: 0, head: null });
      }
      const commit = async (rollback = false, value: unknown = material, legacy = false) => {
        const client = await worker.connect();
        try {
          await client.query('begin');
          await setContext(client);
          const result = await client.query(
            legacy
              ? 'select openpc.commit_fleet_fact_admission($1,$2,$3) inserted'
              : 'select openpc.commit_fleet_fact_admission_v2($1,$2,$3,$4) inserted',
            legacy
              ? capability(value, 'OPENPC_FLEET_FACT_ADMISSION_V1')
              : [...capability(value), profileDigest],
          );
          await client.query(rollback ? 'rollback' : 'commit');
          return result.rows[0].inserted;
        } catch (error) {
          await client.query('rollback');
          throw error;
        } finally {
          client.release();
        }
      };
      await expect(commit(false, material, true)).rejects.toThrow('PC-AUTH-0005');
      expect(await counts()).toEqual({ n: 0, head: null });
      await expect(commit()).rejects.toThrow();
      expect(await counts()).toEqual({ n: 0, head: null });
      const claimed = await beginDelivery(material, currentLease);
      expect(claimed).toMatchObject({ state: 'LEASED', leaseId: currentLease });
      expect(await beginDelivery(material, currentLease)).toEqual(claimed);
      expect(await beginDelivery(material, id())).toEqual({ state: 'BUSY' });
      expect(await commit(true)).toBe(true);
      expect(await counts()).toEqual({ n: 0, head: '0' });
      expect((await Promise.all([commit(), commit()])).sort()).toEqual([false, true]);
      expect(await counts()).toEqual({ n: 1, head: '1' });
      await expect(
        commit(false, { ...material, factDigest: `sha256:${'cd'.repeat(32)}` }),
      ).rejects.toThrow('FLEET-FACT-CONFLICT');
      expect(await commit()).toBe(false);
      // Legacy capabilities can read their exact historical result but cannot
      // introduce an unfenced effect after migration.
      expect(await commit(false, material, true)).toBe(false);
      const stored = await admin.query(
        'select consumer_profile_digest,material from control.fleet_fact_admission_inbox where participant_id=$1',
        [participant],
      );
      expect(stored.rows[0]).toEqual({
        consumer_profile_digest: profileDigest,
        material: Buffer.from(canonicalJson(material)),
      });
      const nextCandidate = id();
      const next = {
        ...material,
        candidateId: nextCandidate,
        sequence: '2',
        envelope: {
          ...material.envelope,
          id: id(),
          subject: `urn:openpc:resource:${nextCandidate}`,
          sequence: '2',
        },
      };
      await expect(commit(false, next, true)).rejects.toThrow('PC-AUTH-0005');
      const capacityLease = id();
      expect(await beginDelivery(next, capacityLease)).toMatchObject({ state: 'LEASED' });
      expect(await failDelivery(next, capacityLease, 'CAPACITY_RELEASE')).toBe('WAITING');
      expect(
        (
          await admin.query(
            'select failed_attempts from control.fleet_fact_delivery where event_id=$1',
            [next.envelope.id],
          )
        ).rows[0].failed_attempts,
      ).toBe(0);
      expect(await beginDelivery(next, id())).toMatchObject({ state: 'WAITING' });
      for (let attempt = 1; attempt <= 3; attempt++) {
        await waitDue(next.envelope.id);
        const firstLease = id(),
          secondLease = id();
        const claims = await Promise.all([
          beginDelivery(next, firstLease),
          beginDelivery(next, secondLease),
        ]);
        expect(claims.map((v) => v.state).sort()).toEqual(['BUSY', 'LEASED']);
        const lease = claims.find((v) => v.state === 'LEASED').leaseId;
        const state = attempt === 3 ? 'EXHAUSTED' : 'WAITING';
        expect(await failDelivery(next, lease)).toBe(state);
        expect(await failDelivery(next, lease)).toBe(state);
        expect(await counts()).toEqual({ n: 1, head: '1' });
      }
      expect(await beginDelivery(next, id())).toEqual({ state: 'EXHAUSTED' });
      const history = (
        await admin.query(
          `select outcome,problem from control.fleet_fact_delivery_attempt where event_id=$1 order by lease_generation`,
          [next.envelope.id],
        )
      ).rows;
      expect(history).toEqual(
        ['CAPACITY_RELEASE', 'FAILED', 'FAILED', 'FAILED'].map((outcome) => ({
          outcome,
          problem: 'PC-DATA-6005',
        })),
      );
      await expect(
        admin.query(
          "update control.fleet_fact_delivery_attempt set outcome='ACTIVE',ended_at_ms=null where event_id=$1",
          [next.envelope.id],
        ),
      ).rejects.toThrow('PC-DATA-6007');
      await expect(
        admin.query('update control.fleet_fact_delivery set failed_attempts=0 where event_id=$1', [
          next.envelope.id,
        ]),
      ).rejects.toThrow('PC-DATA-6007');
      const successor = async (revision: string, lifetimeMs: number, maximumAttempts: number) => {
        const now = Number(
          (await admin.query('select floor(extract(epoch from clock_timestamp())*1000)::text now'))
            .rows[0].now,
        );
        const value: FactConsumerProfile = {
          ...profile,
          revision,
          validFromMs: now - 1000,
          validUntilMs: now + lifetimeMs,
          maximumAttempts,
        };
        const signedPayload = encodeFactConsumerProfile(value),
          signedCose = signFactConsumerProfile(issuerPrivate, issuerSpki, signedPayload);
        const digest = factConsumerProfileDigest(signedCose);
        const client = await admin.connect();
        try {
          await installFactConsumerProfile(
            client,
            { ...value, issuerSpkiDer: issuerSpki, signedProfileDigest: digest },
            signedPayload,
            signedCose,
            'Governed test consumer successor',
          );
        } finally {
          client.release();
        }
        profileDigest = digest;
      };
      // An actual short-lived profile bounds the lease. Expiry and successor
      // installation use real database time; no event, attempt or clock is seeded.
      await successor('2', 1500, 1);
      const crashCandidate = id();
      const crash = {
        ...material,
        candidateId: crashCandidate,
        factType: 'RELATIONSHIP',
        envelope: {
          ...material.envelope,
          id: id(),
          subject: `urn:openpc:resource:${crashCandidate}`,
        },
      };
      const crashLease = id();
      expect(await beginDelivery(crash, crashLease)).toMatchObject({ state: 'LEASED' });
      await admin.query(
        `select pg_sleep(greatest(0,lease_until_ms/1000-extract(epoch from clock_timestamp()))+0.01)
        from control.fleet_fact_delivery where event_id=$1`,
        [crash.envelope.id],
      );
      await expect(beginDelivery(crash, id())).rejects.toThrow('PC-AUTH-0005');
      await successor('3', 3600000, 10);
      expect(await beginDelivery(crash, id())).toEqual({ state: 'EXHAUSTED' });
      expect(await beginDelivery(next, id())).toEqual({ state: 'EXHAUSTED' });
      expect(
        (
          await admin.query(
            'select failed_attempts,maximum_attempts,state from control.fleet_fact_delivery where event_id=$1',
            [crash.envelope.id],
          )
        ).rows[0],
      ).toEqual({ failed_attempts: 1, maximum_attempts: 1, state: 'EXHAUSTED' });
      expect(
        (
          await admin.query(
            'select outcome from control.fleet_fact_delivery_attempt where event_id=$1',
            [crash.envelope.id],
          )
        ).rows,
      ).toEqual([{ outcome: 'LEASE_EXPIRED' }]);
      await expect(failDelivery(crash, crashLease)).rejects.toThrow('PC-AUTH-0005');
      const failurePair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const failurePublic = failurePair.publicKey.export({ format: 'der', type: 'spki' });
      const failurePrivate = failurePair.privateKey.export({ format: 'der', type: 'pkcs8' });
      const failureSigner = evidenceKeyId(failurePublic);
      const quarantineCounts = async () =>
        (
          await admin.query(
            `select
        (select count(*)::int from control.fleet_fact_quarantine where participant_id=$1) receipts,
        (select count(*)::int from control.fleet_fact_failure_outbox where participant_id=$1) outbox,
        (select count(*)::int from control.work_item where participant_id=$1 and kind='FLEET_FAILURE') items`,
            [participant],
          )
        ).rows[0];
      const quarantine = async (value: typeof material, mode = 'commit') => {
        const client = await worker.connect();
        try {
          await client.query('begin');
          await setContext(client, mode === 'cross-privacy' ? otherPrivacy : privacy);
          const request = {
            participantId: participant,
            privacyDomainId: privacy,
            eventId: value.envelope.id,
            signerKeyId: failureSigner,
          };
          const prepared = (
            await client.query('select openpc.prepare_fleet_fact_quarantine($1,$2,$3,$4) result', [
              ...capability(request, 'OPENPC_FLEET_FACT_FAILURE_PREPARE_V1'),
              profileDigest,
            ])
          ).rows[0].result;
          if (prepared.state === 'COMMITTED') {
            await client.query('rollback');
            return prepared;
          }
          expect(prepared.state).toBe('PREPARED');
          expect(prepared.signerSpki).toBe(failurePublic.toString('hex'));
          const claims = prepared.claims as FactConsumerFailure;
          expect(claims.eventId).toBe(value.envelope.id);
          expect(claims.failedAttempts).toBe(claims.maximumAttempts);
          expect(claims.currentProfileDigest).toBe(profileDigest);
          if (mode === 'unfinished') {
            await client.query('commit');
            throw Error('unfinished reservation committed');
          }
          const payload = encodeFactConsumerFailure(
            mode === 'wrong-item' ? { ...claims, workItemId: id() } : claims,
          );
          const cose = signFactConsumerFailure(failurePrivate, failurePublic, payload);
          expect(verifyFactConsumerFailureSignature(failurePublic, payload, cose)).toBe(true);
          if (mode === 'wrong-header') cose[0] = 0xd3;
          const commitRequest = {
            participantId: participant,
            privacyDomainId: privacy,
            eventId: value.envelope.id,
            payload: payload.toString('hex'),
            cose: cose.toString('hex'),
          };
          const cap = capability(commitRequest, 'OPENPC_FLEET_FACT_FAILURE_COMMIT_V1');
          if (mode === 'wrong-mac') cap[2] = Buffer.alloc(32);
          const result = (
            await client.query('select openpc.commit_fleet_fact_quarantine($1,$2,$3,$4) item', [
              ...cap,
              profileDigest,
            ])
          ).rows[0];
          expect(result.item).toBe(claims.workItemId);
          await client.query(mode === 'rollback' ? 'rollback' : 'commit');
          return {
            state: 'COMMITTED',
            receiptId: claims.receiptId,
            workItemId: claims.workItemId,
            payload: payload.toString('hex'),
            cose: cose.toString('hex'),
            receiptDigest: `sha256:${createHash('sha256').update(cose).digest('hex')}`,
          };
        } catch (error) {
          await client.query('rollback');
          throw error;
        } finally {
          client.release();
        }
      };
      await expect(quarantine(next)).rejects.toThrow('PC-AUTH-0005');
      expect(await quarantineCounts()).toEqual({ receipts: 0, outbox: 0, items: 0 });
      await admin.query('create role openpc_failure_privileged_worker login');
      await admin.query(
        'grant openpc_control_worker,openpc_control_owner to openpc_failure_privileged_worker',
      );
      await expect(
        admin.query(
          `insert into control.fact_consumer_failure_signer(participant_id,privacy_domain_id,consumer_id,signer_key_id,public_key_spki,environment_id,database_role,workload_credential_id,workload_credential_epoch,signer_role,purpose_code,valid_from_ms,valid_until_ms,admission_reference)
        values($1,$2,'LS-FLEET-CONTROL',$3,$4,$5,'openpc_failure_privileged_worker',$6,1,'FACT_CONSUMER_FAILURE',344,$7,$8,'Rejected privileged signer role')`,
          [
            participant,
            privacy,
            failureSigner,
            failurePublic,
            profile.environmentId,
            workloadCredential,
            profile.validFromMs,
            profile.validUntilMs,
          ],
        ),
      ).rejects.toThrow('PC-AUTH-0005');
      const secretRoot = await mkdtemp(
        join(process.env.OPENPC_PNC_TMP_ROOT!, 'fleet-failure-initial-'),
      );
      const initial = await admin.connect();
      try {
        const keyBytes = Buffer.from(
          failurePair.privateKey.export({ format: 'jwk' }).d!,
          'base64url',
        );
        await writeFile(
          join(secretRoot, 'fleet_fact_failure_signing_key.txt'),
          keyBytes.toString('hex'),
          { mode: 0o600 },
        );
        keyBytes.fill(0);
        expect(
          await installInitialFleetFailureSigner(initial, secretRoot, participant, privacy),
        ).toBe(failureSigner);
        expect(
          await installInitialFleetFailureSigner(initial, secretRoot, participant, privacy),
        ).toBe(failureSigner);
      } finally {
        initial.release();
        await rm(secretRoot, { recursive: true, force: true });
      }
      await expect(quarantine(material)).rejects.toThrow('PC-DATA-6007');
      for (const mode of [
        'unfinished',
        'wrong-item',
        'wrong-header',
        'wrong-mac',
        'cross-privacy',
      ]) {
        await expect(quarantine(next, mode)).rejects.toThrow();
        expect(await quarantineCounts()).toEqual({ receipts: 0, outbox: 0, items: 0 });
        expect(await counts()).toEqual({ n: 1, head: '1' });
      }
      await quarantine(next, 'rollback');
      expect(await quarantineCounts()).toEqual({ receipts: 0, outbox: 0, items: 0 });
      const [quarantined, replayed] = await Promise.all([quarantine(next), quarantine(next)]);
      expect(replayed).toEqual(quarantined);
      expect(await quarantine(next)).toEqual(quarantined);
      expect(await quarantineCounts()).toEqual({ receipts: 1, outbox: 1, items: 1 });
      expect(await counts()).toEqual({ n: 1, head: '1' });
      const initialItem = (
        await admin.query(
          `select w.*,q.claims,q.payload,q.cose,q.receipt_digest from control.work_item w join control.fleet_fact_quarantine q on q.work_item_id=w.work_item_id where w.work_item_id=$1`,
          [quarantined.workItemId],
        )
      ).rows[0];
      const projection = factConsumerFailureWorkItem(initialItem.claims);
      expect(initialItem.state).toBe('OPEN');
      expect(initialItem.kind).toBe(projection.kind);
      expect(initialItem.resource_ref).toBe(projection.resourceRef);
      expect(initialItem.payload_digest.toString('hex')).toBe(projection.payloadDigest.slice(7));
      expect(initialItem.reason).toBe(projection.reason);
      expect(initialItem.created_by_principal_id).toBe(workloadPrincipal);
      expect(initialItem.assignee_principal_id).toBeNull();
      expect(initialItem.claimed_by_principal_id).toBeNull();
      expect(initialItem.completed_by_principal_id).toBeNull();
      expect(
        verifyFactConsumerFailureSignature(failurePublic, initialItem.payload, initialItem.cose),
      ).toBe(true);
      expect(
        (
          await admin.query('select state from control.fleet_fact_delivery where event_id=$1', [
            next.envelope.id,
          ])
        ).rows[0].state,
      ).toBe('QUARANTINED');
      expect(
        (
          await admin.query(
            'select outcome,problem from control.fleet_fact_delivery_attempt where event_id=$1 order by lease_generation',
            [next.envelope.id],
          )
        ).rows,
      ).toEqual(history);
      await admin.query(
        "update control.fact_consumer_failure_signer set state='REVOKED' where signer_key_id=$1",
        [failureSigner],
      );
      await expect(quarantine(crash)).rejects.toThrow('PC-AUTH-0005');
      expect(await quarantine(next)).toEqual(quarantined);
      expect(await quarantineCounts()).toEqual({ receipts: 1, outbox: 1, items: 1 });
      failurePrivate.fill(0);
      await verifyFleetFailureCustody(
        admin,
        worker,
        participant,
        privacy,
        otherPrivacy,
        initialItem.cose,
      );
      nativeAdmission(privacy, profileDigest, false);
      await admin.query(
        "update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1",
        [workloadCredential],
      );
      await expect(commit(false, next)).rejects.toThrow('PC-AUTH-0005');
      nativeAdmission(privacy, profileDigest, true);
      nativeAdmission(otherPrivacy, initialDigest, true);
      const revokedInstaller = await admin.connect();
      try {
        await expect(
          installInitialFleetConsumerProfile(
            revokedInstaller,
            participant,
            otherPrivacy,
            workloadCredential,
          ),
        ).rejects.toThrow('current real workload');
      } finally {
        revokedInstaller.release();
      }
      expect(await counts()).toEqual({ n: 1, head: '1' });
      // Readback of an already committed effect preserves its original identity
      // and bytes even after the workload loses authority for new effects.
      expect(await commit()).toBe(false);
      expect(await commit(false, material, true)).toBe(false);
      const client = await worker.connect();
      try {
        for (const table of [
          'fleet_fact_admission_inbox',
          'fleet_fact_admission_cursor',
          'fleet_fact_admission_key',
        ]) {
          await expect(client.query(`delete from control.${table}`)).rejects.toThrow(
            'permission denied',
          );
        }
        await expect(
          client.query('select verifier_secret from control.fleet_fact_admission_key'),
        ).rejects.toThrow('permission denied');
        await client.query('begin');
        await setContext(client, otherPrivacy);
        expect(
          (await client.query('select * from control.fleet_fact_admission_inbox')).rowCount,
        ).toBe(0);
        await client.query('rollback');
      } finally {
        client.release();
      }
      expect(await counts()).toEqual({ n: 1, head: '1' });
    } finally {
      secret.fill(0);
      issuerPrivate.fill(0);
      await worker.end();
      await admin.end();
    }
  },
  30000,
);
