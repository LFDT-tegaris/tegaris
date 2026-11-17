import { createHash, generateKeyPairSync } from 'node:crypto';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { RuntimeSnapshotPublisher } from '../../../services/identity-service/src/domain/runtime-snapshot-publisher.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { runtimeTargetProfileBindingDigest } from '../../../services/control-api/src/configuration/runtime-profile/digest.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const identityUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && identityUrl ? it : it.skip;
const action = 'ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1';
const sha = (value: Buffer) => createHash('sha256').update(value).digest();

integration(
  'governs immutable target profiles and publishes stable target-bound Identity context',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const controlUrl = new URL(identityUrl!);
    controlUrl.username = 'openpc_configuration_runtime';
    const control = new Pool({ connectionString: controlUrl.href, max: 2 });
    const identity = new Pool({ connectionString: identityUrl, max: 1 });
    const participantId = id(),
      privacyDomainId = id();
    const fixture = await contractAdministrationFixture(
      admin,
      identityUrl!,
      participantId,
      privacyDomainId,
      { configurationRuntime: control },
    );
    const workloadId = `urn:openpc:workload:${id()}`,
      principalId = id();
    const uriSan = `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`;
    const tls = await runtimeSnapshotTlsFixture(uriSan);
    let completed = false;
    try {
      // Independent initial transport trust only. No workload envelope, assignment,
      // approval, activation, policy or invocation permission is seeded here.
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD','Pre-existing publication subject','ACTIVE',1)`,
        [principalId, participantId],
      );
      const publicKey = tls.parsed.publicKey.export({ format: 'der', type: 'spki' });
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS','local-test-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          id(),
          participantId,
          principalId,
          uriSan,
          workloadId,
          sha(publicKey),
          publicKey,
          sha(tls.parsed.raw),
          new Date(tls.parsed.validFrom),
          new Date(tls.parsed.validTo),
        ],
      );
      const target = async () => {
        const response = await fixture
          .ordinaryMutation('runtime-targets', 'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1', {
            participantId: `urn:openpc:participant:${participantId}`,
            desiredGenerationDigest: null,
            activeGenerationDigest: null,
            xdsVersionDigest: null,
            observedAt: '2026-10-14T00:00:00.000000Z',
          })
          .call();
        expect(response.status, JSON.stringify(response)).toBe(202);
        return String(response.body.resourceRef).slice(-36);
      };
      const a = await target(),
        b = await target(),
        forgedTarget = await target();
      const keys = generateKeyPairSync('ed25519');
      const crypto = createLocalIdentityRuntimeCryptoAdapter({
        activePrivateKeyPkcs8Der: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
        activePublicKeySpkiDer: keys.publicKey.export({ format: 'der', type: 'spki' }),
        trustedPublicKeysSpkiDer: [keys.publicKey.export({ format: 'der', type: 'spki' })],
      });
      const publisher = new RuntimeSnapshotPublisher(
        crypto,
        {
          profileId: 'pc.identity.r1.workload-mtls',
          profileVersion: 1n,
          applicability: [1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1],
          profileClass: 1,
          signerId: 'local-test-identity',
        },
        { scope: ['workload', 'test-ca', 'TLS1.3-X509'], state: { trust: 'local-test-ca-v1' } },
      );
      const publish = (targetRuntimeId: string) =>
        runScopedTransaction(
          identity,
          {
            participantId,
            privacyDomainId,
            actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
          },
          id,
          (client) =>
            publisher.refreshTargetSnapshot(client, participantId, {
              privacyDomainId,
              targetRuntimeId,
            }),
        );
      const absentSnapshot = await publish(a); // actual Identity SQL role, mapping absent
      const fields = (runtimeTargetId: string, targetProfileId: string, targetRevision = '1') => ({
        runtimeTargetRef: `urn:openpc:resource:${runtimeTargetId}`,
        targetProfileId,
        targetRevision,
      });
      const prepared = await fixture.prepareCreation(
        'runtime-target-profile-bindings',
        action,
        fields(a, 'devnet-rpc-v1'),
        true,
      );
      expect((await prepared.commit()).status).toBe(403); // maker proof remains mandatory
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.runtime_target_profile_binding where participant_id=$1',
            [participantId],
          )
        ).rows[0].n,
      ).toBe(0);
      await prepared.stepUp();
      expect(
        (await prepared.commit({ ...prepared.body, targetProfileId: 'substituted' })).status,
      ).toBe(412);
      expect((await prepared.propose()).status).toBe(200);
      const committed = await prepared.commit();
      expect(committed.status, JSON.stringify(committed)).toBe(202);
      expect(await prepared.commit()).toEqual(committed);
      await fixture.restartConfiguration();
      const view = await fixture.read(
        `runtime-target-profile-bindings/${committed.body.resourceRef}`,
      );
      expect(view.status, JSON.stringify(view)).toBe(200);
      expect(view.body).toMatchObject({
        targetRef: `urn:openpc:resource:${a}`,
        targetProfileId: 'devnet-rpc-v1',
        revision: '1',
        runtimePermission: 'NONE_WITHOUT_MATCHING_ENVELOPE',
        bindingDigest: runtimeTargetProfileBindingDigest({
          participantId,
          privacyDomainId,
          targetRuntimeId: a,
          targetProfileId: 'devnet-rpc-v1',
        }),
      });
      const mappedSnapshot = await publish(a);
      expect(mappedSnapshot.snapshotId).not.toBe(absentSnapshot.snapshotId);
      expect((await publish(a)).snapshotId).toBe(mappedSnapshot.snapshotId);
      for (const candidate of [
        fields(b, 'devnet-rpc-v1'),
        fields(a, 'different-profile'),
        fields(b, 'stale-profile', '2'),
      ]) {
        const denied = await fixture.prepareCreation(
          'runtime-target-profile-bindings',
          action,
          candidate,
          true,
        );
        await denied.stepUp();
        expect(await denied.commit()).toMatchObject({
          status: 412,
          body: { code: 'PC-DATA-6007', truthState: 'STALE', retryable: false },
        });
      }
      const boundB = await fixture.prepareCreation(
        'runtime-target-profile-bindings',
        action,
        fields(b, 'second-profile'),
        true,
      );
      await boundB.stepUp();
      expect((await boundB.commit()).status).toBe(202);
      const versions = async () =>
        (
          await admin.query(
            `select domain_code,encode(scope_digest,'hex') scope,version::text,encode(source_state_digest,'hex') state
      from control.identity_runtime_authority_scope where participant_id=$1 order by domain_code,scope`,
            [participantId],
          )
        ).rows;
      await publish(a);
      const original = await versions();
      await publish(b);
      expect(await versions()).toEqual(original);
      await publish(a);
      expect(await versions()).toEqual(original);
      const payloads = (
        await admin.query(
          `select convert_from(content.payload,'UTF8')::jsonb payload from control.identity_runtime_snapshot_content content
      join control.identity_runtime_snapshot snapshot on snapshot.participant_id=content.participant_id and snapshot.snapshot_id=content.snapshot_id
      where snapshot.participant_id=$1 and content.content_kind='ROLE_ASSIGNMENTS'`,
          [participantId],
        )
      ).rows.map((r) => r.payload);
      expect(
        payloads.some(
          (p) =>
            p.runtime_target_profile?.runtime_target_id === a &&
            p.runtime_target_profile?.target_profile_id === 'devnet-rpc-v1',
        ),
      ).toBe(true);
      expect(
        payloads.some(
          (p) =>
            p.runtime_target_profile?.runtime_target_id === b &&
            p.runtime_target_profile?.target_profile_id === 'second-profile',
        ),
      ).toBe(true);
      expect(payloads.every((p) => p.paths.length === 0)).toBe(true); // mapping cannot manufacture a grant
      const forgedId = id(),
        operationId = id();
      await expect(
        runScopedTransaction(
          control,
          { participantId, privacyDomainId, actionIntentId: action },
          () => operationId,
          (client) =>
            client.query(
              `insert into control.runtime_target_profile_binding(binding_id,participant_id,privacy_domain_id,runtime_target_id,target_revision,target_profile_id,binding_digest,publication_operation_id,publication_authority_digest)
       values($1,$2,$3,$4,1,'unapproved-profile',$5,$6,$7)`,
              [
                forgedId,
                participantId,
                privacyDomainId,
                forgedTarget,
                runtimeTargetProfileBindingDigest({
                  participantId,
                  privacyDomainId,
                  targetRuntimeId: forgedTarget,
                  targetProfileId: 'unapproved-profile',
                }),
                operationId,
                `sha256:${'0'.repeat(64)}`,
              ],
            ),
        ),
      ).rejects.toMatchObject({
        code: 'P0001',
        message: 'PC-AUTH-0005-RUNTIME-PROFILE-PROVENANCE',
      });
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.runtime_target_profile_binding where participant_id=$1',
            [participantId],
          )
        ).rows[0].n,
      ).toBe(2);
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.mutation_evidence where participant_id=$1 and aggregate_type='runtime-target-profile-binding'`,
            [participantId],
          )
        ).rows[0].n,
      ).toBe(2);
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.outbox_event where participant_id=$1 and event_type='openpc.runtime-target.profile-bound.v1'`,
            [participantId],
          )
        ).rows[0].n,
      ).toBe(2);
      completed = true;
    } finally {
      await fixture.close();
      await control.end();
      await identity.end();
      await admin.end();
      if (completed) await tls.close(); // Retain failed publication's original transport keys.
    }
  },
  120_000,
);
