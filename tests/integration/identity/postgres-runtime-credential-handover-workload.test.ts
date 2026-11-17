import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { cp, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { workloadRotationAuthority } from './workload-rotation-pki.js';
import {
  installRuntimeWorkloadInitialTrust,
  grantRuntimeWorkloadSourceRead,
  renewRuntimeHandoverWorkload,
} from './runtime-credential-handover-workload.js';
import { closeFixtureResources } from './close-fixture-resources.js';
import { digest } from './public-governance-client.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { createLocalWorkloadIssuerFixture } from '../local-runtime/workload-issuer-runtime.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

// Minimum real owning-database prerequisite. This does not start the native
// worker/SDK, install a source/policy, or qualify handover/serving permission.
integration(
  'grants a target workload through public approval and renews its actually expired credential without changing the grant',
  async () => {
    const parent = process.env.OPENPC_TEST_TMP_ROOT;
    if (!parent?.startsWith('/')) throw new Error('Absolute isolated test scratch is required');
    const root = await mkdtemp(join(parent, 'native-handover-workload-'));
    const admin = new Pool({ connectionString: adminUrl, max: 2 }),
      runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    const rolePool = (role: string) => {
      const url = new URL(runtimeUrl!);
      url.username = role;
      return new Pool({ connectionString: url.href, max: 2 });
    };
    const control = rolePool('openpc_configuration_runtime'),
      participant = rolePool('openpc_participant_runtime');
    const participantId = id(),
      privacyDomainId = id(),
      successorId = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let installedIssuer: Awaited<ReturnType<typeof createLocalWorkloadIssuerFixture>> | undefined;
    let issuer: ReturnType<typeof createServer> | undefined,
      issuanceRequests = 0;
    let failure: { error: unknown } | undefined;
    try {
      const authority = await workloadRotationAuthority(root, participantId),
        token = randomBytes(32).toString('hex');
      issuer = createServer((request, response) => {
        if (!installedIssuer) {
          response.writeHead(503).end();
          return;
        }
        installedIssuer.emit('request', request, response);
      });
      await new Promise<void>((resolve, reject) => {
        issuer!.once('error', reject);
        issuer!.listen(0, '127.0.0.1', resolve);
      });
      issuer.on('request', (request) => {
        if (request.method === 'POST' && request.url === '/v1/certificates') issuanceRequests++;
      });
      fixture = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        privacyDomainId,
        {
          principalKind: 'PLATFORM_OPERATOR',
          initialParticipantRole: true,
          initialRuntimeSourceReadTrust: true,
          configurationRuntime: control,
          participantRuntime: participant,
          workloadIssuer: {
            url: `http://127.0.0.1:${(issuer.address() as AddressInfo).port}/v1/certificates`,
            token,
            trustedCaPem: authority.ca,
          },
        },
      );
      const target = await fixture
        .ordinaryMutation('runtime-targets', 'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1', {
          participantId: `urn:openpc:participant:${participantId}`,
          desiredGenerationDigest: null,
          activeGenerationDigest: null,
          xdsVersionDigest: null,
          observedAt: new Date().toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
        })
        .call();
      expect(target, JSON.stringify(target)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      const targetId = String(target.body.resourceRef).slice(-36);
      // REGISTERED is not qualification. This fixture tests a real scope-bound
      // public grant only; full native testing supplies its real parsed artifact.
      const indexer = await fixture
        .ordinaryMutation('indexer-profiles', 'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1', {
          participantId: `urn:openpc:participant:${participantId}`,
          engine: 'CLIENT_INDEXER',
          engineVersion: '1.0.0',
          methodProfileDigest: digest({ purpose: 'external-source-scope-input' }),
        })
        .call();
      expect(indexer, JSON.stringify(indexer)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      const indexerId = String(indexer.body.resourceRef).slice(-36);
      const pki = await authority.bindWorkload(`urn:openpc:workload:${targetId}`, {
        runtimeTargetId: targetId,
        initiallyCurrent: true,
        initialCredentialLifetimeMs: 30000,
      });
      const initial = await pki.issueInitialPredecessor();
      const workload = await installRuntimeWorkloadInitialTrust(admin, fixture, targetId, initial);
      installedIssuer = await createLocalWorkloadIssuerFixture({
        token,
        manifest: [
          {
            credentialId: successorId,
            participantId,
            principalId: workload.principalId,
            workloadId: workload.workloadId,
            publicKeySpkiDer: pki.successor.publicKey.toString('base64'),
            certificateDer: pki.successor.certificate.raw.toString('base64'),
          },
        ],
      });
      expect(issuanceRequests).toBe(0);
      const grant = await grantRuntimeWorkloadSourceRead(admin, fixture, workload, indexerId);
      // Public grant setup must complete while the original actual leaf is live.
      expect(new Date(initial.certificate.validTo).getTime()).toBeGreaterThan(Date.now());
      const original = (
        await admin.query(
          'select to_jsonb(a) source from control.assignment a where participant_id=$1 and assignment_id=$2',
          [participantId, grant.assignmentId],
        )
      ).rows;
      expect(original).toHaveLength(1);
      const remaining = new Date(initial.certificate.validTo).getTime() - Date.now() + 50;
      if (remaining > 0) await delay(remaining);
      await renewRuntimeHandoverWorkload(admin, runtime, fixture, workload, {
        ...pki.successor,
        credentialId: successorId,
      });
      expect(issuanceRequests).toBe(1);
      expect(
        (
          await admin.query(
            'select to_jsonb(a) source from control.assignment a where participant_id=$1 and assignment_id=$2',
            [participantId, grant.assignmentId],
          )
        ).rows,
      ).toEqual(original);
      const targetRead = await fixture.read(`runtime-targets/${target.body.resourceRef}`);
      expect(targetRead.status, JSON.stringify(targetRead)).toBe(200);
      expect(targetRead.body.activeGenerationDigest).toBeNull();
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.policy_generation where participant_id=$1',
            [participantId],
          )
        ).rows,
      ).toEqual([{ n: 0 }]);
    } catch (error) {
      failure = { error };
      const secondary: unknown[] = [];
      if (fixture) {
        try {
          await cp(fixture.service.directory, join(root, 'failed-identity-runtime'), {
            recursive: true,
            errorOnExist: true,
            force: false,
          });
        } catch (e) {
          secondary.push(e);
        }
        try {
          await writeFile(
            join(root, 'failed-synthetic-actors.private.json'),
            JSON.stringify({
              maker: fixture.governance.maker,
              checker: fixture.governance.checker,
              devices: [...fixture.governance.devices].map(([principalId, device]) => ({
                principalId,
                credentialId: device.credentialId,
                count: device.count,
                privateKeyPkcs8Base64: device.privateKey
                  .export({ format: 'der', type: 'pkcs8' })
                  .toString('base64'),
              })),
            }),
            { flag: 'wx', mode: 0o600 },
          );
        } catch (e) {
          secondary.push(e);
        }
      }
      if (secondary.length)
        failure = {
          error: new AggregateError(
            [error, ...secondary],
            'Workload test failed; evidence retention incomplete',
          ),
        };
    }
    await closeFixtureResources(
      [
        () => fixture?.close(),
        () =>
          issuer?.listening
            ? new Promise<void>((resolve, reject) =>
                issuer!.close((e) => (e ? reject(e) : resolve())),
              )
            : undefined,
        () => runtime.end(),
        () => control.end(),
        () => participant.end(),
        () => admin.end(),
      ],
      failure,
    );
    if (failure) throw failure.error;
    await rm(root, { recursive: true, force: true });
  },
  120000,
);
