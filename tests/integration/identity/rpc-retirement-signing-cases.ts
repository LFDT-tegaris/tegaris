import { execFile } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { createFixtureSigningProvider } from '../local-runtime/signing-provider-fixture.js';
import {
  rpcRetirementSigningFamilies,
  rpcRetirementSigningProfiles,
  rpcRetirementSigningWorkload,
} from '../local-runtime/rpc-retirement-signing.js';
import {
  discoverBusinessSigningKey,
  fenceBusinessSigningKey,
} from '../../../services/identity-service/src/db/business-signing-store.js';

const execute = promisify(execFile);
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const integration = adminUrl ? it : it.skip;

integration(
  'admits distinct current RPC retirement signing trust without business effects or retry replacement',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const participantId = '018f0000-0000-7000-8000-000000000101';
    const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'rpc-retirement-signing-'));
    const secrets = join(root, 'secrets'),
      providerRoot = join(root, 'provider');
    let provider: Awaited<ReturnType<typeof createFixtureSigningProvider>> | undefined;
    try {
      expect(
        (
          await admin.query(
            `select 1 from control.participant p join control.privacy_domain d using(participant_id) where p.participant_id=$1 and d.privacy_domain_id=$2 and p.state='ACTIVE' and d.state='ACTIVE'`,
            [participantId, privacyDomainId],
          )
        ).rowCount,
      ).toBe(1);
      await mkdir(secrets);
      const prepare = (extra: string[]) =>
        execute(
          process.execPath,
          [
            '--import',
            'tsx',
            'tests/integration/local-runtime/signing-provider-bootstrap.ts',
            secrets,
            providerRoot,
            ...extra,
          ],
          { timeout: 15000 },
        );
      await prepare([]);
      const historicalPublic = await readFile(
        join(secrets, 'control_business_signing_public_key.der'),
      );
      await writeFile(
        join(secrets, 'identity_runtime_signing_public_key.der'),
        generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
          type: 'spki',
          format: 'der',
        }),
      );
      await prepare(['--rpc-retirement', privacyDomainId]);
      const transport = join(secrets, 'rpc-retirement-transport');
      const read = (name: string) => readFile(join(transport, name));
      provider = await createFixtureSigningProvider({
        root: providerRoot,
        initialKeys: [],
        certificate: await read('business_provider_server_cert.pem'),
        privateKey: await read('business_provider_server_key.pem'),
        ca: await read('business_provider_ca.pem'),
        clients: [
          {
            participantId,
            privacyDomainId,
            environmentId: 'local',
            credentialId: rpcRetirementSigningWorkload.credentialId,
            workloadId: rpcRetirementSigningWorkload.workloadId,
            certificate: await read('business_api_cert.pem'),
            methods: ['INSPECT'],
            managedKeyOwners: [rpcRetirementSigningWorkload.credentialId],
            signingProfiles: [],
          },
        ],
      });
      await new Promise<void>((resolve) => provider!.server.listen(0, '127.0.0.1', resolve));
      const address = provider.server.address();
      if (!address || typeof address === 'string') throw new Error('Expected TCP fixture');
      const effects = async () =>
        (
          await admin.query(
            `select
      (select count(*) from control.deletion_job where participant_id=$1)::int jobs,
      (select count(*) from control.mutation_candidate where participant_id=$1)::int candidates,
      (select count(*) from control.audit_occurrence where participant_id=$1)::int receipts,
      (select count(*) from control.outbox_event where participant_id=$1)::int events`,
            [participantId],
          )
        ).rows;
      const before = await effects();
      const admit = () =>
        execute(
          process.execPath,
          [
            '--import',
            'tsx',
            'tests/integration/local-runtime/business-signing-bootstrap.mjs',
            secrets,
            participantId,
            privacyDomainId,
            '--rpc-retirement-trust',
          ],
          {
            timeout: 20000,
            env: {
              ...process.env,
              OPENPC_SIGNING_BOOTSTRAP_DATABASE_URL: adminUrl!,
              OPENPC_SIGNING_BOOTSTRAP_PROVIDER_ORIGIN: `https://127.0.0.1:${address.port}`,
            },
          },
        );
      await admit();
      expect(await effects()).toEqual(before);
      const snapshot = async () =>
        (
          await admin.query(
            `select k.signer_id,k.trust_preimage,k.trust_digest,p.profile_id,p.profile_version,s.row_version
      from control.business_signing_key k join control.business_signing_selection s using(participant_id,privacy_domain_id,signer_id)
      join control.business_transition_profile p using(profile_digest)
      where k.participant_id=$1 and k.privacy_domain_id=$2 and k.workload_credential_id=$3 order by p.profile_id,p.profile_version`,
            [participantId, privacyDomainId, rpcRetirementSigningWorkload.credentialId],
          )
        ).rows;
      const admitted = await snapshot();
      expect(admitted).toHaveLength(3);
      expect(new Set(admitted.map((row) => row.signer_id)).size).toBe(3);
      await admit();
      expect(await snapshot()).toEqual(admitted);
      expect(await effects()).toEqual(before);
      expect(await readFile(join(secrets, 'control_business_signing_public_key.der'))).toEqual(
        historicalPublic,
      );
      const client = await admin.connect();
      try {
        await client.query('begin');
        for (const { family } of rpcRetirementSigningFamilies) {
          const profile = rpcRetirementSigningProfiles(family)[0]!;
          const scope = {
            participantId,
            privacyDomainId,
            environmentId: 'local',
            profileId: profile.profileId,
            profileVersion: profile.profileVersion,
            profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
            actionIntentId: profile.actionIntentId,
            catalogOperationId: profile.catalogOperationId,
          };
          const discovery = await discoverBusinessSigningKey(client, scope);
          const fenced = await fenceBusinessSigningKey(client, scope, discovery);
          expect(fenced.trust.workloadCredentialId).toBe(rpcRetirementSigningWorkload.credentialId);
          expect(fenced.trust.grants).toHaveLength(1);
          expect(fenced.trust.grants[0]!.profileVersion).toBe(profile.profileVersion);
        }
      } finally {
        await client.query('rollback');
        client.release();
      }
    } finally {
      await provider?.close();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  60000,
);
