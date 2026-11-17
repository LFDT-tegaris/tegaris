import { createECDH, generateKeyPairSync, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import {
  encodeFactConsumerProfile,
  evidenceKeyId,
  factConsumerProfileDigest,
  signFactConsumerProfile,
  type FactConsumerProfile,
  type InstalledFactConsumerProfile,
} from '../../../packages/security-kernel/src/index.js';
import {
  installFactConsumerProfile,
  requireFactConsumerProfile,
} from '../../../services/control-api/src/fact-consumers/profile-store.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runtimeSourceLogin } from '../../../packages/security-kernel/src/runtime-source-identity.js';
import { factConsumerDatabaseRoleSql } from '../../../services/control-api/src/fact-consumers/database-role-sql.mjs';
import { installInitialFleetFailureSigner } from '../local-runtime/fact-failure-bootstrap.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;
function key() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }),
  };
}

// Initial workload and installation trust only. This database test establishes
// neither mTLS peer authentication nor a real delivery/retry/quarantine effect.
integration.each(['legacy', 'rooted'] as const)(
  '%s: binds immutable installed profile history to exact live workload and revocation locks',
  async (mode) => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    // Docker reports bare addresses; PostgreSQL inet::text includes /32 or
    // /128. Actual session readback must compare host(client_addr).
    const address = (
      await admin.query<{ raw: string; host: string }>(
        'select inet_client_addr()::text as raw,host(inet_client_addr()) as host',
      )
    ).rows[0]!;
    expect(address.raw).not.toBe(address.host);
    expect(
      (
        await admin.query<{ matched: boolean }>(
          'select host(client_addr)=$1::text as matched from pg_catalog.pg_stat_activity where pid=pg_backend_pid()',
          [address.host],
        )
      ).rows[0]!.matched,
    ).toBe(true);
    const participant = id(),
      privacy = id(),
      otherPrivacy = id(),
      principal = id(),
      credential = id();
    const issuer = key(),
      workload = key();
    let actualWorkerUrl = workerUrl!;
    if (mode === 'rooted') {
      const role = runtimeSourceLogin(participant, privacy);
      const password = randomBytes(32).toString('hex');
      const ddl = await admin.query<{ create: string; grant: string }>(
        "select format('create role %I login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password %L',$1::text,$2::text) as create,format('grant openpc_control_worker to %I',$1::text) as grant",
        [role, password],
      );
      await admin.query(ddl.rows[0]!.create);
      await admin.query(ddl.rows[0]!.grant);
      const url = new URL(workerUrl!);
      url.username = role;
      url.password = password;
      actualWorkerUrl = url.href;
    }
    const worker = new Pool({ connectionString: actualWorkerUrl, max: 2 });
    const role = (await worker.query<{ name: string }>('select current_user as name')).rows[0]!
      .name;
    const nativeAdmission = (
      blocked: boolean,
      digest: string,
      connectionString = actualWorkerUrl,
    ) => {
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
            OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL: connectionString,
            OPENPC_FACT_CONSUMER_PARTICIPANT: participant,
            OPENPC_FACT_CONSUMER_PRIVACY: privacy,
            OPENPC_FACT_CONSUMER_DIGEST: digest,
            OPENPC_FACT_CONSUMER_EXPECT_BLOCKED: blocked ? '1' : '0',
          },
        },
      );
      expect(output).toContain('1 passed; 0 failed');
    };
    const now = Date.now();
    const profile: FactConsumerProfile = {
      environmentId: 'consumer-postgres',
      participantId: participant,
      privacyDomainId: privacy,
      profileId: 'fact-admission',
      revision: '1',
      consumerId: 'LS-FLEET-CONTROL',
      subscriptionId: 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1',
      validFromMs: now - 60000,
      validUntilMs: now + 3600000,
      issuerKeyId: evidenceKeyId(issuer.publicKey),
      workloadCredentialId: credential,
      workloadCredentialEpoch: '1',
      databaseRole: role,
      maximumAttempts: 3,
      initialBackoffMs: 100,
      maximumBackoffMs: 1000,
    };
    const signed = (claims: FactConsumerProfile) => {
      const payload = encodeFactConsumerProfile(claims);
      const cose = signFactConsumerProfile(issuer.privateKey, issuer.publicKey, payload);
      const installed: InstalledFactConsumerProfile = {
        issuerSpkiDer: issuer.publicKey,
        signedProfileDigest: factConsumerProfileDigest(cose),
        environmentId: claims.environmentId,
        participantId: participant,
        privacyDomainId: privacy,
        profileId: claims.profileId,
        revision: claims.revision,
        consumerId: claims.consumerId,
        subscriptionId: claims.subscriptionId,
        workloadCredentialId: credential,
        workloadCredentialEpoch: claims.workloadCredentialEpoch,
        databaseRole: role,
      };
      return { payload, cose, installed };
    };
    const first = signed(profile);
    const context = (client: PoolClient, scope = privacy) =>
      client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-OPERATIONS_READ_OPERATION-V1',true)",
        [participant, scope, id()],
      );
    const read = async (installed = first.installed, scope = privacy) => {
      const client = await worker.connect();
      try {
        await client.query('begin');
        await context(client, scope);
        return await requireFactConsumerProfile(client, installed);
      } finally {
        await client.query('rollback');
        client.release();
      }
    };
    const install = async (value: ReturnType<typeof signed>) => {
      const client = await admin.connect();
      try {
        await installFactConsumerProfile(
          client,
          value.installed,
          value.payload,
          value.cose,
          'Initial local consumer test trust',
        );
      } finally {
        client.release();
      }
    };
    try {
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Consumer test','ACTIVE',1)",
        [participant],
      );
      for (const domain of [privacy, otherPrivacy])
        await admin.query(
          "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,$1::uuid::text,'PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
          [domain, participant],
        );
      await admin.query(
        "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Consumer workload','ACTIVE',1)",
        [principal, participant],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,state,credential_epoch,valid_from,valid_until,secret_fingerprint)
      values($1,$2,$3,'WORKLOAD_MTLS','urn:openpc:consumer-test-ca',$1::uuid::text,'consumer-test',$4,$5,'ACTIVE',1,
      clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',$4)`,
        [
          credential,
          participant,
          principal,
          Buffer.from(evidenceKeyId(workload.publicKey).slice(7), 'hex'),
          workload.publicKey,
        ],
      );
      await expect(read()).rejects.toThrow();
      const badSignature = Buffer.from(first.cose);
      badSignature[badSignature.length - 1]! ^= 1;
      await expect(
        install({
          ...first,
          cose: badSignature,
          installed: {
            ...first.installed,
            signedProfileDigest: factConsumerProfileDigest(badSignature),
          },
        }),
      ).rejects.toThrow();
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.fact_consumer_profile where participant_id=$1',
            [participant],
          )
        ).rows[0].n,
      ).toBe(0);
      await install(first);
      expect(await read()).toEqual(profile);
      nativeAdmission(false, first.installed.signedProfileDigest);
      if (mode === 'rooted') {
        // An exact derived name is syntax, not a substitute for session identity.
        nativeAdmission(true, first.installed.signedProfileDigest, workerUrl);
        for (const [candidateRole, scope, allowed] of [
          [role, privacy, true],
          [role, otherPrivacy, false],
          [role.toUpperCase(), privacy, false],
          [`${role}=`, privacy, false],
          [`${role.slice(0, -1)}!`, privacy, false],
          ['OtherRole', privacy, false],
          ['openpc_local_control_worker', privacy, true],
        ] as const) {
          const predicate = factConsumerDatabaseRoleSql('$1::text', '$2::uuid', '$3::uuid');
          // This producer feeds future generated migrations. Applied migration
          // bytes stay immutable; new output must not introduce line-end space.
          expect(predicate).toBe(predicate.trimEnd());
          expect(predicate).not.toMatch(/[\t ]+$/mu);
          expect(
            (
              await admin.query(`select ${predicate} as allowed`, [
                candidateRole,
                participant,
                scope,
              ])
            ).rows[0].allowed,
          ).toBe(allowed);
        }
        const root = await mkdtemp(
          join(process.env.OPENPC_TEST_TMP_ROOT!, 'scoped-failure-signer-'),
        );
        const curve = createECDH('prime256v1');
        curve.generateKeys();
        await writeFile(
          join(root, 'fleet_fact_failure_signing_key.txt'),
          curve.getPrivateKey().toString('hex'),
          { mode: 0o600 },
        );
        const client = await admin.connect();
        try {
          await installInitialFleetFailureSigner(client, root, participant, privacy);
          const signer = await admin.query(
            'select database_role from control.fact_consumer_failure_signer where participant_id=$1 and privacy_domain_id=$2',
            [participant, privacy],
          );
          expect(signer.rows).toEqual([{ database_role: role }]);
        } finally {
          client.release();
          await rm(root, { recursive: true, force: true });
        }
      }
      await expect(read(first.installed, otherPrivacy)).rejects.toThrow();
      await expect(read({ ...first.installed, consumerId: 'LS-CONTROL-WORK' })).rejects.toThrow();
      for (const databaseRole of [
        'openpc_control_runtime',
        'openpc_control_reader',
        'openpc_control_worker',
      ]) {
        for (const privilege of ['INSERT', 'UPDATE', 'DELETE'])
          expect(
            (
              await admin.query(
                "select has_table_privilege($1,'control.fact_consumer_profile',$2) allowed",
                [databaseRole, privilege],
              )
            ).rows[0].allowed,
          ).toBe(false);
        expect(
          (
            await admin.query(
              "select has_function_privilege($1,'openpc.require_fact_consumer_profile(text)','EXECUTE') allowed",
              [databaseRole],
            )
          ).rows[0].allowed,
        ).toBe(databaseRole === 'openpc_control_worker');
      }
      await expect(
        admin.query('update control.fact_consumer_profile set revision=2 where participant_id=$1', [
          participant,
        ]),
      ).rejects.toThrow();
      await expect(
        admin.query('delete from control.fact_consumer_profile where participant_id=$1', [
          participant,
        ]),
      ).rejects.toThrow();
      await expect(install(first)).rejects.toThrow();
      await expect(install(signed({ ...profile, revision: '3' }))).rejects.toThrow();
      // Both the exact workload row and its principal must stay fenced until the
      // consuming transaction ends; no successful revocation race is fabricated.
      const held = await worker.connect();
      const contender = await admin.connect();
      try {
        await held.query('begin');
        await context(held);
        await requireFactConsumerProfile(held, first.installed);
        for (const [table, column, value] of [
          ['credential', 'credential_id', credential],
          ['principal', 'principal_id', principal],
        ]) {
          await contender.query('begin');
          await expect(
            contender.query(`select 1 from control.${table} where ${column}=$1 for update nowait`, [
              value,
            ]),
          ).rejects.toMatchObject({ code: '55P03' });
          await contender.query('rollback');
        }
      } finally {
        await held.query('rollback');
        await contender.query('rollback');
        held.release();
        contender.release();
      }
      const successor = signed({ ...profile, revision: '2', maximumAttempts: 2 });
      await install(successor);
      await expect(read()).rejects.toThrow();
      expect((await read(successor.installed)).maximumAttempts).toBe(2);
      const history = await admin.query(
        'select payload,cose from control.fact_consumer_profile where participant_id=$1 and revision=1',
        [participant],
      );
      expect(history.rows[0].payload).toEqual(first.payload);
      expect(history.rows[0].cose).toEqual(first.cose);
      await admin.query("update control.credential set state='REVOKED' where credential_id=$1", [
        credential,
      ]);
      await expect(read(successor.installed)).rejects.toThrow();
      nativeAdmission(true, successor.installed.signedProfileDigest);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.fact_consumer_profile where participant_id=$1',
            [participant],
          )
        ).rows[0].n,
      ).toBe(2);
    } finally {
      issuer.privateKey.fill(0);
      workload.privateKey.fill(0);
      await Promise.all([admin.end(), worker.end()]);
    }
  },
);
