import { createHash, createPrivateKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join } from 'node:path';
import { writeFile, rm } from 'node:fs/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { decodeCbor } from '../../../packages/security-kernel/src/canonical-cbor.js';
import {
  decodeIdentityAuthContextAssertionPayload,
  verifyIdentityAuthContextAssertionCoseSign1Ed25519,
  verifyIdentityRuntimeSnapshotManifestCoseSign1Ed25519,
} from '../../../packages/security-kernel/src/index.js';
import {
  PostgresIdentityRepository,
  IdentityKernel,
  type AuthenticatedWorkloadIdentity,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { RuntimeSnapshotPublisher } from '../../../services/identity-service/src/domain/runtime-snapshot-publisher.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { readAuthoritySnapshotRows } from '../../../services/identity-service/src/db/authority-snapshot.js';
import { buildLocalWorkloadMtlsService } from '../../../services/identity-service/src/domain/local-workload-mtls.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';

const adminUrl = process.env.OPENPC_ASTRA05_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_ASTRA05_RUNTIME_DATABASE_URL;
const integration = adminUrl === undefined || runtimeUrl === undefined ? it.skip : it;
const sha = (value: string | Buffer) => createHash('sha256').update(value).digest();

// SQL-owner regression. Bootstrap authority below does not prove the governed
// grant journey; the deployed protected-target acceptance owns that proof.
integration(
  'publishes complete scoped identity state atomically with certificate authentication',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const runtime = new Pool({ connectionString: runtimeUrl });
    const participantId = id(),
      privacyDomainId = id(),
      foreignPrivacyId = id(),
      principalId = id();
    const grantorId = id(),
      delegationId = id();
    const groupId = id(),
      connectorId = id(),
      oidcCredentialId = id();
    let groupFreshUntilNs: string;
    const targetRuntimeId = id(),
      credentialId = id(),
      assignmentId = id(),
      envelopeId = id();
    const platformContextId = id();
    const workloadId = `urn:openpc:workload:${id()}`;
    const keys = generateKeyPairSync('ed25519');
    const publicDer = keys.publicKey.export({ format: 'der', type: 'spki' });
    const crypto = createLocalIdentityRuntimeCryptoAdapter({
      activePrivateKeyPkcs8Der: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
      activePublicKeySpkiDer: publicDer,
      trustedPublicKeysSpkiDer: [publicDer],
    });
    const publisher = (adapter = crypto) =>
      new RuntimeSnapshotPublisher(
        adapter,
        {
          profileId: 'pc.identity.r1.workload-mtls',
          profileVersion: 1n,
          applicability: [1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1],
          profileClass: 1,
          signerId: 'local-test-identity',
        },
        {
          scope: ['local-workload-provider', 'local-test-ca', 'TLS1.3-X509'],
          state: { trust: 'local-test-ca-v1' },
        },
      );
    const repository = new PostgresIdentityRepository(runtime, systemClock, crypto, publisher());
    const uriSan = `urn:openpc:participant:${participantId}:workload:${workloadId.split(':').at(-1)}`;
    const tls = await runtimeSnapshotTlsFixture(uriSan);
    const workloadPublicDer = tls.parsed.publicKey.export({ format: 'der', type: 'spki' });
    const mtls = buildLocalWorkloadMtlsService(runtime, new IdentityKernel(repository), tls.server);
    const input = {
      participantId,
      workloadId,
      participantEpoch: '1',
      workloadEpoch: '1',
      keyId: `sha256:${sha(workloadPublicDer).toString('hex')}`,
      uriSan,
      certificateFingerprint: sha(tls.parsed.raw),
      tlsVersion: 'TLS1.3' as const,
      notBefore: new Date(tls.parsed.validFrom),
      notAfter: new Date(tls.parsed.validTo),
      issuerTrusted: true,
      keyTrusted: true,
      revoked: false,
    };
    const context = { privacyDomainId, targetRuntimeId };
    const scoped = <T>(
      operation: Parameters<typeof runScopedTransaction<T>>[3],
      privacy = privacyDomainId,
    ) =>
      runScopedTransaction(
        runtime,
        {
          participantId,
          privacyDomainId: privacy,
          actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        },
        id,
        operation,
      );
    // Initial trust fixture, not runtime authority or a discovery journey. The
    // runtime transaction owner correctly rejects superuser connections.
    const installInitialTarget = async (target: string) => {
      const client = await admin.connect();
      try {
        await client.query('begin');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          [participantId, privacyDomainId, id()],
        );
        await client.query(
          `insert into control.runtime_target
          (runtime_target_id,participant_id,privacy_domain_id,state,observed_at,policy_generation_digest)
          values($1,$2,$3,'DISCOVERED',clock_timestamp(),$4)`,
          [
            target,
            participantId,
            privacyDomainId,
            `sha256:${sha('fixture-policy').toString('hex')}`,
          ],
        );
        await client.query('commit');
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
    };
    try {
      await admin.query(`insert into control.action_intent values
      ('ACT-POLICY_READ_EFFECTIVE_ACCESS-V1','identity','READ','LOW',false,false,false,'AUTHORIZED_ONLY','REDACTED','IDENTITY',default,default)
      on conflict do nothing`);
      await admin.query(`insert into control.action_intent values
      ('ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1','fact-artifacts','UPDATE','STANDARD',false,false,true,
       'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_FACT_ARTIFACTS',default,default) on conflict do nothing`);

      await admin.query(
        `insert into control.participant (participant_id,display_name,state,authority_epoch)
      values ($1,'snapshot regression','ACTIVE',1)`,
        [participantId],
      );
      await admin.query(
        `insert into control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version)
         values($1,$2,'ACTIVE',7,1)`,
        [platformContextId, participantId],
      );
      for (const privacy of [privacyDomainId, foreignPrivacyId])
        await admin.query(
          `insert into control.privacy_domain (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
       values ($1::uuid,$2,$1::text,'PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE')`,
          [privacy, participantId],
        );
      await admin.query(
        `insert into control.principal (principal_id,participant_id,kind,display_label,state,authority_epoch)
      values ($1,$2,'WORKLOAD','snapshot workload','ACTIVE',1)`,
        [principalId, participantId],
      );
      await admin.query(
        `insert into control.principal (principal_id,participant_id,kind,display_label,state,authority_epoch)
          values ($1,$2,'USER','snapshot grantor','ACTIVE',1)`,
        [grantorId, participantId],
      );
      await admin.query(
        `insert into control.credential
      (credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,
       secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values ($1,$2,$3,'WORKLOAD_MTLS','local-test-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          credentialId,
          participantId,
          principalId,
          uriSan,
          workloadId,
          sha(workloadPublicDer),
          workloadPublicDer,
          input.certificateFingerprint,
          input.notBefore,
          input.notAfter,
        ],
      );
      await installInitialTarget(targetRuntimeId);
      const roleId = `urn:openpc:role:${id()}`;
      await admin.query(
        `insert into control.authority_role
         (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
         values ($1,$2,$3,'Runtime snapshot initial trust',$4,'BOOTSTRAP',$5)`,
        [
          roleId.slice(-36),
          participantId,
          roleId,
          [
            'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
            'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',
            'ACT-RUNTIME_READ_RPC-V1',
          ],
          grantorId,
        ],
      );
      await admin.query(
        `insert into control.authority_envelope
      (authority_envelope_id,participant_id,principal_id,maker_principal_id,authority_epoch,delegation_epoch,state,
       valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
       maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
      values ($1,$2,$3,$3,1,1,'ACTIVE',$4,$5,$6,$5,$7,$8,array['*'],array['LOW','STANDARD'],false,false,2,$9,7)`,
        [
          envelopeId,
          participantId,
          grantorId,
          input.notBefore,
          Buffer.from([0x80]),
          sha(envelopeId),
          [privacyDomainId],
          ['ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'],
          platformContextId,
        ],
      );
      await admin.query('insert into control.identity_subject (identity_subject_id) values ($1)', [
        grantorId,
      ]);
      await admin.query(
        'insert into control.participant_membership (membership_id,participant_id,identity_subject_id) values ($1,$2,$1)',
        [grantorId, participantId],
      );
      await admin.query(
        "insert into control.authority_group (authority_group_id,participant_id,group_name,state) values ($1,$2,'Snapshot local group','ACTIVE')",
        [groupId, participantId],
      );
      // Retained owner-state fixture for publication/consumption only. The real
      // approval and source-observation journey is tested in postgres-directory-journey.
      await admin.query(
        `insert into control.directory_connector(connector_id,participant_id,profile_id,profile_digest,display_name,external_group_freshness_seconds)
        values($1,$2,$3,$4,'Snapshot directory',60)`,
        [connectorId, participantId, id(), sha('profile')],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,state,valid_from)
        values($1,$2,$3,'OIDC_SUBJECT','https://snapshot-provider.invalid','external-grantor','snapshot','ACTIVE',clock_timestamp())`,
        [oidcCredentialId, participantId, grantorId],
      );
      await admin.query(
        `insert into control.directory_member(participant_id,connector_id,external_id,principal_id,oidc_credential_id,provider_version,provider_modified_at,observed_at,source_digest,last_mutation_operation_id)
        values($1,$2,'external-grantor',$3,$4,'W/"1"',clock_timestamp(),clock_timestamp(),$5,$6)`,
        [participantId, connectorId, grantorId, oidcCredentialId, sha('member'), id()],
      );
      groupFreshUntilNs = (
        await admin.query(
          `insert into control.directory_group_mapping(participant_id,authority_group_id,connector_id,external_group_id,profile_digest,provider_version,provider_modified_at,source_digest,source_member_ids,observed_at,fresh_until,last_mutation_operation_id)
        values($1,$2,$3,'external-group',$4,'W/"1"',$5,$6,ARRAY['external-grantor'],$5,$5::timestamptz+interval '60 seconds',$7)
        returning (extract(epoch from fresh_until)*1000000000)::numeric(20,0)::text deadline`,
          [participantId, groupId, connectorId, sha('profile'), new Date(), sha('group'), id()],
        )
      ).rows[0].deadline;
      await admin.query(
        "insert into control.authority_group_member (participant_id,authority_group_id,principal_id,valid_during) values ($1,$2,$3,tstzrange($4,null,'[)'))",
        [participantId, groupId, grantorId, input.notBefore],
      );
      await admin.query(
        `insert into control.assignment
      (assignment_id,participant_id,principal_id,role_id,authority_envelope_id,delegation_epoch,scope_digest,
       privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
       onward_delegation_depth,valid_during,state,created_by_principal_id,authority_group_id)
      values ($1,$2,$3,$4,$5,1,$6,$7,$8,array['*'],array['LOW','STANDARD'],false,false,1,tstzrange($9,null,'[)'),'ACTIVE',$3,$10)`,
        [
          assignmentId,
          participantId,
          grantorId,
          roleId,
          envelopeId,
          sha(assignmentId),
          [privacyDomainId],
          ['ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'],
          input.notBefore,
          groupId,
        ],
      );
      await admin.query(
        `insert into control.delegation
         (delegation_id,participant_id,parent_assignment_id,grantor_principal_id,delegate_principal_id,
          delegation_epoch,scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
          maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state)
         values ($1,$2,$3,$4,$5,1,$6,$7,$8,array['*'],array['LOW','STANDARD'],false,false,0,tstzrange($9,null,'[)'),'ACTIVE')`,
        [
          delegationId,
          participantId,
          assignmentId,
          grantorId,
          principalId,
          sha(delegationId),
          [privacyDomainId],
          ['ACT-POLICY_READ_EFFECTIVE_ACCESS-V1', 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'],
          input.notBefore,
        ],
      );
      const address = await mtls.listen({ host: '127.0.0.1', port: 0 });
      const authenticated = await tls.post(`${address}/internal/v1/workload/authenticate`, {
        runtimeContext: context,
      });
      expect(authenticated.status).toBe(200);
      const first = authenticated.body as AuthenticatedWorkloadIdentity;
      expect(first.runtime).toBeDefined();
      const assertionBytes = Buffer.from(first.runtime!.assertionPayload, 'base64');
      expect(
        verifyIdentityAuthContextAssertionCoseSign1Ed25519(
          publicDer,
          assertionBytes,
          Buffer.from(first.runtime!.assertionCoseSign1, 'base64'),
        ),
      ).toBe(true);
      const assertion = decodeIdentityAuthContextAssertionPayload(assertionBytes);
      expect(assertion.expiresAtNs).toBeLessThanOrEqual(BigInt(groupFreshUntilNs));
      expect(assertion.senderCredentialBindingDigest).toEqual(input.certificateFingerprint);
      const readback = await scoped(async (client) => ({
        snapshot: (
          await client.query(
            `select * from control.identity_runtime_snapshot where snapshot_id=$1`,
            [first.runtime!.snapshotId],
          )
        ).rows[0],
        content: (
          await client.query<{ content_kind: string; payload: Buffer }>(
            `select content_kind,payload from control.identity_runtime_snapshot_content where snapshot_id=$1`,
            [first.runtime!.snapshotId],
          )
        ).rows,
        versions: (
          await client.query<{ domain_code: number; version: string }>(
            `select domain_code,version::text from control.identity_runtime_authority_scope order by domain_code`,
          )
        ).rows,
      }));
      expect(readback.snapshot.actor_count).toBe(1);
      const scopedGrants = JSON.parse(
        readback.content.find((c) => c.content_kind === 'ROLE_ASSIGNMENTS')!.payload.toString(),
      );
      expect(scopedGrants.credentials).toHaveLength(1);
      expect(scopedGrants.credentials[0]).toMatchObject({
        credential_id: credentialId,
        principal_id: principalId,
        subject: uriSan,
        audience: workloadId,
        fingerprint: input.certificateFingerprint.toString('hex'),
        public_key_digest: sha(workloadPublicDer).toString('hex'),
        state: 'ACTIVE',
        epoch: '1',
        valid_now: true,
        valid_from_ns: (BigInt(input.notBefore.getTime()) * 1_000_000n).toString(),
        valid_until_ns: (BigInt(input.notAfter.getTime()) * 1_000_000n).toString(),
      });
      expect(scopedGrants.paths[0][0].grant.group_scope).toMatchObject({
        group_id: groupId,
        principal_id: grantorId,
        group_revision: '1',
        active: true,
        valid_until_ns: null,
        fresh_until_ns: groupFreshUntilNs,
      });
      expect(BigInt(readback.snapshot.expires_at_ns)).toBe(BigInt(groupFreshUntilNs));
      expect(
        readback.content.find((c) => c.content_kind === 'ROLE_ASSIGNMENTS')!.payload.toString(),
      ).not.toContain('external-group');
      for (const content of readback.content) {
        for (const field of [
          'last_mutation_operation_id',
          'bootstrap_mandate_id',
          'bootstrap_platform_participant_id',
          'creator_participant_id',
        ])
          expect(content.payload.toString()).not.toContain(field);
      }
      expect(
        verifyIdentityRuntimeSnapshotManifestCoseSign1Ed25519(
          publicDer,
          readback.snapshot.manifest_payload,
          readback.snapshot.manifest_cose,
        ),
      ).toBe(true);
      expect(readback.versions.map((v) => [v.domain_code, v.version])).toEqual(
        [1, 2, 4, 6, 7, 9, 12].map((d) => [d, '1']),
      );
      const shard = decodeCbor(
        readback.content.find((c) => c.content_kind === 'SHARD')!.payload,
      ) as Map<number, unknown>;
      const state = (shard.get(3) as Map<number, unknown>[])[0]!;
      expect((state.get(0) as Map<number, unknown>).get(5)).toEqual(
        assertion.authorityVectorDigest,
      );
      expect(
        readback.content.find((c) => c.content_kind === 'ROLE_ASSIGNMENTS')!.payload.toString(),
      ).toContain(roleId);
      expect(
        (
          await scoped(
            (client) => client.query(`select snapshot_id from control.identity_runtime_snapshot`),
            foreignPrivacyId,
          )
        ).rowCount,
      ).toBe(0);
      await expect(
        repository.authenticateWorkload(input, { ...context, privacyDomainId: foreignPrivacyId }),
      ).rejects.toThrow();
      await expect(
        repository.authenticateWorkload(
          { ...input, certificateFingerprint: sha('wrong-cert') },
          context,
        ),
      ).rejects.toMatchObject({ code: 'PC-IDENTITY-1006' });
      const resumed = new PostgresIdentityRepository(runtime, systemClock, crypto, publisher());
      const second = await resumed.authenticateWorkload(input, context);
      expect(second.runtime!.snapshotId).toBe(first.runtime!.snapshotId);
      expect(second.runtime!.assertionPayload).not.toBe(first.runtime!.assertionPayload);
      const factConsumer = process.env.OPENPC_FACT_WORKLOAD_TEST_BINARY;
      if (factConsumer !== undefined) {
        const file = join(process.env.OPENPC_TEST_TMP_ROOT!, 'fact-workload-input.json');
        await writeFile(
          file,
          JSON.stringify({
            participant: participantId,
            privacy: privacyDomainId,
            target: targetRuntimeId,
            principal: principalId,
            assignment: assignmentId,
            envelope: envelopeId,
            platform: platformContextId,
            endpoint: `${address}/internal/v1/workload/authenticate`,
            ca: [...new X509Certificate(tls.server.ca).raw],
            certificate: [...tls.parsed.raw],
            private_key: [
              ...createPrivateKey(tls.privateKey).export({ format: 'der', type: 'pkcs8' }),
            ],
            server_digest: sha(new X509Certificate(tls.server.certificate).raw).toString('hex'),
            identity_key: [...publicDer],
            profile_digest: readback.snapshot.profile_digest.toString('hex'),
          }),
          { mode: 0o600 },
        );
        try {
          const result = await promisify(execFile)(
            factConsumer,
            [
              'workload_authority::tests::installed_mtls_identity_requires_current_scoped_fact_permission',
              '--ignored',
              '--exact',
              '--nocapture',
            ],
            {
              env: { ...process.env, OPENPC_FACT_WORKLOAD_TEST_INPUT_FILE: file },
              timeout: 20_000,
            },
          );
          expect(result.stdout).toContain('1 passed');
        } finally {
          await rm(file, { force: true });
        }
      }
      const unsignedTarget = id();
      await installInitialTarget(unsignedTarget);
      const lastUse = (
        await admin.query(
          `select last_used_at::text from control.credential where credential_id=$1`,
          [credentialId],
        )
      ).rows;
      const unavailableSigner = {
        ...crypto,
        async signCanonicalAssertion(): Promise<never> {
          throw new Error('test signer unavailable');
        },
      };
      const blocked = new PostgresIdentityRepository(
        runtime,
        systemClock,
        unavailableSigner,
        publisher(unavailableSigner),
      );
      await expect(
        blocked.authenticateWorkload(input, { ...context, targetRuntimeId: unsignedTarget }),
      ).rejects.toThrow('test signer unavailable');
      expect(
        (
          await admin.query(
            `select last_used_at::text from control.credential where credential_id=$1`,
            [credentialId],
          )
        ).rows,
      ).toEqual(lastUse);
      expect(
        (
          await scoped((client) =>
            client.query(
              `select snapshot_id from control.identity_runtime_snapshot where target_runtime_id=$1`,
              [unsignedTarget],
            ),
          )
        ).rowCount,
      ).toBe(0);
      await expect(
        scoped((client) => client.query(`delete from control.identity_runtime_authority_scope`)),
      ).rejects.toThrow();
      await expect(
        scoped((client) =>
          client.query(
            `update control.identity_runtime_authority_scope set version=version+1 where domain_code=6`,
          ),
        ),
      ).rejects.toThrow();
      await expect(
        scoped((client) =>
          client.query(`update control.identity_runtime_snapshot set actor_count=2`),
        ),
      ).rejects.toThrow();
      const beforeRevocationVersion = BigInt(
        (
          await scoped((client) =>
            client.query(
              'select version::text from control.identity_runtime_authority_scope where domain_code=6',
            ),
          )
        ).rows[0].version,
      );
      await admin.query(
        `update control.assignment set state='REVOKED',row_version=row_version+1 where assignment_id=$1`,
        [assignmentId],
      );
      const revoked = await resumed.authenticateWorkload(input, context);
      expect(revoked.runtime!.snapshotId).not.toBe(first.runtime!.snapshotId);
      const after = decodeIdentityAuthContextAssertionPayload(
        Buffer.from(revoked.runtime!.assertionPayload, 'base64'),
      );
      expect(after.authorityVectorDigest).not.toEqual(assertion.authorityVectorDigest);
      expect(
        (
          await scoped((client) =>
            client.query(
              `select version::text from control.identity_runtime_authority_scope where domain_code=6`,
            ),
          )
        ).rows,
      ).toEqual([{ version: (beforeRevocationVersion + 1n).toString() }]);
      await admin.query(
        `update control.assignment set state='ACTIVE',row_version=row_version+1 where assignment_id=$1`,
        [assignmentId],
      );
      const regranted = await resumed.authenticateWorkload(input, context);
      expect(regranted.runtime!.snapshotId).not.toBe(first.runtime!.snapshotId);
      expect(
        (
          await scoped((client) =>
            client.query(
              `select version::text from control.identity_runtime_authority_scope where domain_code=6`,
            ),
          )
        ).rows,
      ).toEqual([{ version: (beforeRevocationVersion + 2n).toString() }]);
      // These SQL mutations exercise publication/target consumption only. The
      // supported governed grant journey must separately create its own states.
      for (const [table, key, value] of [
        ['authority_envelope', 'authority_envelope_id', envelopeId],
        ['assignment', 'assignment_id', assignmentId],
        ['delegation', 'delegation_id', delegationId],
      ]) {
        for (const invalid of [['eth_call'], ['SEALED_INTERNAL_SAFETY_PREFLIGHT'], [null]]) {
          await expect(
            admin.query(`update control.${table} set runtime_capability_ids=$2 where ${key}=$1`, [
              value,
              invalid,
            ]),
          ).rejects.toMatchObject({ code: '23514' });
        }
        await admin.query(
          `update control.${table} set action_intent_ids=array['ACT-RUNTIME_READ_RPC-V1'],runtime_capability_ids=array['CALL_RESULT_DISCLOSURE'],row_version=row_version+1 where ${key}=$1`,
          [value],
        );
      }
      const runtimeGranted = await resumed.authenticateWorkload(input, context);
      expect(runtimeGranted.runtime!.snapshotId).not.toBe(regranted.runtime!.snapshotId);
      const retained = await scoped((client) =>
        readAuthoritySnapshotRows(client, participantId, {
          assignment: [{ id: assignmentId }],
          authority_envelope: [{ id: envelopeId }],
          delegation: [{ id: delegationId }],
        }),
      );
      for (const table of ['assignment', 'authority_envelope', 'delegation']) {
        expect(retained[table]).toEqual([
          expect.objectContaining({ runtime_capability_ids: '{CALL_RESULT_DISCLOSURE}' }),
        ]);
      }
      await admin.query(
        `update control.assignment set runtime_capability_ids=array[]::text[],row_version=row_version+1 where assignment_id=$1`,
        [assignmentId],
      );
      const runtimeNarrowed = await resumed.authenticateWorkload(input, context);
      expect(runtimeNarrowed.runtime!.snapshotId).not.toBe(runtimeGranted.runtime!.snapshotId);
      await admin.query(
        `update control.assignment set runtime_capability_ids=array['CALL_RESULT_DISCLOSURE'],row_version=row_version+1 where assignment_id=$1`,
        [assignmentId],
      );
      const outputPath = process.env.OPENPC_ASTRA05_PUBLICATION_FIXTURE;
      // The workload itself stays active. Revoking its grantor alone must
      // invalidate the delegated authority and the old assertion vector.
      await admin.query(
        `insert into control.revocation
        (participant_id,target_type,target_id,effective_at,reason_code,authority_epoch,receipt_digest,created_by_principal_id)
        values ($1,'PRINCIPAL',$2,clock_timestamp(),'TEST_GRANTOR_REVOKED',2,$3,$4)`,
        [participantId, grantorId, sha(id()), principalId],
      );
      const publishedState = () =>
        scoped(
          async (client) =>
            (
              await client.query(
                `select s.snapshot_id,s.manifest_digest,s.issued_at_ns,s.expires_at_ns,
                      h.snapshot_id as head_snapshot_id
               from control.identity_runtime_snapshot s
               join control.identity_runtime_snapshot_head h
                 on h.target_runtime_id=s.target_runtime_id
                and h.participant_id=s.participant_id
                and h.privacy_domain_id=s.privacy_domain_id
               where s.target_runtime_id=$1 order by s.snapshot_id`,
                [targetRuntimeId],
              )
            ).rows,
        );
      // A failed publication must leave the committed revocation intact and
      // preserve the previous head and its expiry. The live workload still
      // supplies an audience for the restrictive replacement snapshot.
      const beforeSignerFailure = await publishedState();
      let manifestSigningAttempts = 0;
      const unavailableSnapshotSigner = {
        ...crypto,
        async signCanonicalSnapshotManifest(): Promise<never> {
          manifestSigningAttempts += 1;
          throw new Error('test snapshot signer unavailable');
        },
      };
      expect(
        await publisher(unavailableSnapshotSigner).refreshPublishedTargets(
          runtime,
          participantId,
          privacyDomainId,
        ),
      ).toEqual({ attempted: 1, failed: 1 });
      expect(manifestSigningAttempts).toBe(1);
      expect(await publishedState()).toEqual(beforeSignerFailure);
      expect(
        (
          await admin.query(
            `select target_id from control.revocation
             where participant_id=$1 and target_type='PRINCIPAL' and target_id=$2`,
            [participantId, grantorId],
          )
        ).rows,
      ).toEqual([{ target_id: grantorId }]);
      expect(
        await publisher().refreshPublishedTargets(runtime, participantId, privacyDomainId),
      ).toEqual({ attempted: 1, failed: 0 });
      const afterSignerRecovery = await publishedState();
      expect(afterSignerRecovery).toHaveLength(beforeSignerFailure.length + 1);
      expect(afterSignerRecovery[0].head_snapshot_id).not.toBe(
        beforeSignerFailure[0].head_snapshot_id,
      );
      const ancestorRevoked = await resumed.authenticateWorkload(input, context);
      expect(ancestorRevoked.runtime!.snapshotId).not.toBe(regranted.runtime!.snapshotId);
      if (outputPath !== undefined) {
        const publication = async (identity: AuthenticatedWorkloadIdentity) =>
          scoped(async (client) => {
            const snapshot = (
              await client.query(
                `select * from control.identity_runtime_snapshot where snapshot_id=$1`,
                [identity.runtime!.snapshotId],
              )
            ).rows[0];
            const artifacts = (
              await client.query<{
                content_kind: string;
                content_digest: Buffer;
                ordinal: number;
                payload: Buffer;
              }>(
                `select content_kind,content_digest,ordinal,payload from control.identity_runtime_snapshot_content where snapshot_id=$1 order by ordinal`,
                [identity.runtime!.snapshotId],
              )
            ).rows;
            return {
              manifest_payload: snapshot.manifest_payload.toString('hex'),
              manifest_cose: snapshot.manifest_cose.toString('hex'),
              manifest_digest: snapshot.manifest_digest.toString('hex'),
              profile_payload: snapshot.profile_payload.toString('hex'),
              profile_cose: snapshot.profile_cose.toString('hex'),
              profile_digest: snapshot.profile_digest.toString('hex'),
              verification_time_ns: (BigInt(snapshot.issued_at_ns) + 1_000_000n).toString(),
              assertion_payload: Buffer.from(identity.runtime!.assertionPayload, 'base64').toString(
                'hex',
              ),
              assertion_cose: Buffer.from(identity.runtime!.assertionCoseSign1, 'base64').toString(
                'hex',
              ),
              shards: artifacts
                .filter((a) => a.content_kind === 'SHARD')
                .map((a) => a.payload.toString('hex')),
              content: artifacts.map((a) => ({
                digest: a.content_digest.toString('hex'),
                payload: a.payload.toString('hex'),
              })),
            };
          });
        await writeFile(
          outputPath,
          JSON.stringify({
            participant_id: participantId,
            privacy_domain_id: privacyDomainId,
            target_runtime_id: targetRuntimeId,
            principal_id: principalId,
            role_id: roleId,
            identity_public_key: publicDer.toString('hex'),
            certificate_pem: tls.certificate.toString(),
            uri_san: uriSan,
            first: await publication(first),
            revoked: await publication(revoked),
            regranted: await publication(regranted),
            runtime_granted: await publication(runtimeGranted),
            runtime_narrowed: await publication(runtimeNarrowed),
            ancestor_revoked: await publication(ancestorRevoked),
          }),
          { mode: 0o600 },
        );
      }
      // Revoking the last live credential removes the snapshot audience.
      // Refresh must fail before signing and cannot renew the retained head.
      const beforeCredentialRevocation = await publishedState();
      await admin.query(`update control.credential set state='REVOKED' where credential_id=$1`, [
        credentialId,
      ]);
      await expect(resumed.authenticateWorkload(input, context)).rejects.toThrow();
      expect(
        await publisher(unavailableSnapshotSigner).refreshPublishedTargets(
          runtime,
          participantId,
          privacyDomainId,
        ),
      ).toEqual({ attempted: 1, failed: 1 });
      expect(manifestSigningAttempts).toBe(1);
      expect(await publishedState()).toEqual(beforeCredentialRevocation);
      expect(
        (
          await admin.query(`select state from control.credential where credential_id=$1`, [
            credentialId,
          ])
        ).rows,
      ).toEqual([{ state: 'REVOKED' }]);
      expect(
        await publisher().refreshPublishedTargets(runtime, participantId, foreignPrivacyId),
      ).toEqual({ attempted: 0, failed: 0 });
      await expect(resumed.authenticateWorkload(input, context)).rejects.toThrow();
    } finally {
      await mtls.close();
      await Promise.all([runtime.end(), admin.end()]);
      await tls.close();
    }
  },
  60_000,
);
