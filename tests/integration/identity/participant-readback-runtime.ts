import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import type { DirectoryProfileRegistry } from '../../../services/identity-service/src/domain/directory-profiles.js';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';

import {
  buildLocalIdentityRuntime,
  readLocalIdentityRuntimeConfig,
} from '../../../services/identity-service/src/local-runtime.js';
import { buildPostgresParticipantService } from '../../../services/participant-service/src/app.js';
import { createLocalParticipantIdentityAdapters } from '../../../services/participant-service/src/local-runtime.js';
import { createHttpIdentityEnvelopeSigningProvider } from '../../../services/identity-service/src/domain/http-identity-envelope-signing-provider.js';
import { createHttpIdentityEnvelopeRotationProvider } from '../../../services/identity-service/src/domain/http-identity-envelope-rotation-provider.js';
import { PostgresIdentityEnvelopeRotationAttemptStore } from '../../../services/participant-service/src/identity-envelope-rotation-store.js';
import { IdentityEnvelopeRotationWorker } from '../../../services/participant-service/src/identity-envelope-rotation-worker.js';
import {
  IdentityEnvelopeRotationRuntime,
  installedIdentityEnvelopeRotationScope,
} from '../../../services/participant-service/src/identity-envelope-rotation-runtime.js';
import { closeFixtureResources } from './close-fixture-resources.js';

/** Real HTTP owners; the caller supplies initial database trust and owns its business fixture. */
export async function participantReadbackRuntime(input: {
  runtime: Pool;
  identityDatabaseUrl: string;
  participantId: string;
  privacyDomainId: string;
  operatorPrincipalId: string;
  checkerPrincipalId: string;
  oidc?: { issuer: string; clientId: string; redirectUri: string };
  directoryProfiles?: DirectoryProfileRegistry;
  /** Explicit local recovery fixture only; existing callers keep normal defaults. */
  localQaFixture?: boolean;
  hardwareAttestationProfile?: import('../../../services/identity-service/src/domain/hardware-attestation.js').HardwareAttestationProfile;
  /** Retain original private fixture material under the owning runner scratch. */
  preserveMaterial?: boolean;
  /** External issuer fixture only; Identity still validates its issued bytes. */
  workloadIssuer?: { url: string; token: string; trustedCaPem: Buffer };
  /** Installed external custody only. Proposals, approvals, repair leases and
   * signing effects must still pass their real HTTP/database owners. */
  envelopeSigning?: {
    environmentId: string;
    callerWorkloadCredentialId: string;
    transport: Parameters<typeof createHttpIdentityEnvelopeSigningProvider>[0];
    rotationEnabled?: boolean;
  };
}) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent?.startsWith('/')) throw new Error('Absolute external test scratch is required');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'participant-readback-'));
  let identity: Awaited<ReturnType<typeof buildLocalIdentityRuntime>> | undefined;
  let participant: FastifyInstance | undefined;
  const stopIdentity = async () => {
    const current = identity;
    identity = undefined;
    await closeFixtureResources([
      async () => {
        await current?.app.close();
      },
      async () => {
        await current?.pool.end();
      },
    ]);
  };
  const close = async () => {
    await closeFixtureResources([
      async () => {
        await participant?.close();
      },
      stopIdentity,
    ]);
    if (!input.preserveMaterial) await rm(root, { recursive: true });
  };
  try {
    const database = new URL(input.identityDatabaseUrl);
    const internalToken = randomBytes(32).toString('hex');
    const key = generateKeyPairSync('ed25519');
    const file = (name: string) => join(root, name);
    await Promise.all([
      writeFile(file('internal'), internalToken, { mode: 0o600 }),
      writeFile(file('database'), decodeURIComponent(database.password), { mode: 0o600 }),
      writeFile(file('private.der'), key.privateKey.export({ type: 'pkcs8', format: 'der' }), {
        mode: 0o600,
      }),
      writeFile(file('public.der'), key.publicKey.export({ type: 'spki', format: 'der' })),
    ]);
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-keyout',
        file('tls.key'),
        '-out',
        file('tls.crt'),
        '-days',
        '1',
        '-subj',
        '/CN=OpenPC isolated readback test',
      ],
      { stdio: 'ignore' },
    );
    if (input.workloadIssuer) {
      await writeFile(file('issuer-token'), input.workloadIssuer.token, { mode: 0o600 });
      await writeFile(file('issuer-ca.pem'), input.workloadIssuer.trustedCaPem);
    }
    if (input.hardwareAttestationProfile)
      await writeFile(
        file('hardware-attestation.json'),
        JSON.stringify(input.hardwareAttestationProfile),
      );
    let config = await readLocalIdentityRuntimeConfig({
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: input.localQaFixture ? '1' : '0',
      IDENTITY_DATABASE_HOST: database.hostname,
      IDENTITY_DATABASE_PORT: database.port,
      IDENTITY_DATABASE_NAME: database.pathname.slice(1),
      IDENTITY_DATABASE_USER: decodeURIComponent(database.username),
      IDENTITY_DATABASE_PASSWORD_FILE: file('database'),
      IDENTITY_INTERNAL_TOKEN_FILE: file('internal'),
      IDENTITY_RUNTIME_SIGNING_PRIVATE_KEY_FILE: file('private.der'),
      IDENTITY_RUNTIME_SIGNING_PUBLIC_KEY_FILE: file('public.der'),
      IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES: file('public.der'),
      IDENTITY_LOCAL_OPERATOR_CREDENTIAL_FILE: file('internal'),
      IDENTITY_LOCAL_VIEWER_CREDENTIAL_FILE: file('internal'),
      IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID: input.operatorPrincipalId,
      IDENTITY_LOCAL_VIEWER_PRINCIPAL_ID: input.checkerPrincipalId,
      IDENTITY_LOCAL_PARTICIPANT_ID: input.participantId,
      IDENTITY_LOCAL_PRIVACY_DOMAIN_ID: input.privacyDomainId,
      IDENTITY_OIDC_ISSUER: input.oidc?.issuer ?? 'http://127.0.0.1:1',
      IDENTITY_OIDC_CLIENT_ID: input.oidc?.clientId ?? 'isolated-readback',
      IDENTITY_OIDC_REDIRECT_URI: input.oidc?.redirectUri ?? 'http://127.0.0.1:1/callback',
      ...(input.hardwareAttestationProfile
        ? { IDENTITY_RECOVERY_ATTESTATION_PROFILE_FILE: file('hardware-attestation.json') }
        : {}),
      IDENTITY_MTLS_CA_FILE: file('tls.crt'),
      IDENTITY_WORKLOAD_ISSUER_URL: input.workloadIssuer?.url ?? 'http://127.0.0.1:1',
      IDENTITY_WORKLOAD_ISSUER_TOKEN_FILE: file(input.workloadIssuer ? 'issuer-token' : 'internal'),
      ...(input.workloadIssuer ? { IDENTITY_WORKLOAD_ISSUER_CA_FILE: file('issuer-ca.pem') } : {}),
      IDENTITY_MTLS_SERVER_CERT_FILE: file('tls.crt'),
      IDENTITY_MTLS_SERVER_KEY_FILE: file('tls.key'),
      IDENTITY_MTLS_LISTEN: '127.0.0.1:1',
      IDENTITY_LISTEN: '127.0.0.1:1',
    });
    identity = await buildLocalIdentityRuntime(config, input.directoryProfiles);
    const identityUrl = await identity.app.listen({ host: '127.0.0.1', port: 0 });
    const identityDenials: { path: string; status: number; code?: string }[] = [];
    const adapters = createLocalParticipantIdentityAdapters(
      {
        PARTICIPANT_IDENTITY_URL: identityUrl,
        PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: input.privacyDomainId,
        identityInternalToken: internalToken,
      },
      async (url, init) => {
        const response = await fetch(url, init);
        if (!response.ok) {
          const problem = (await response
            .clone()
            .json()
            .catch(() => ({}))) as { code?: string };
          identityDenials.push({
            path: new URL(typeof url === 'string' || url instanceof URL ? url : url.url).pathname,
            status: response.status,
            code: problem.code,
          });
          if (identityDenials.length > 8) identityDenials.shift();
        }
        return response;
      },
    );
    const startParticipant = async () => {
      // Recreate transports on restart: closing the old app drains its worker
      // and closes both clients without changing the provider's durable state.
      const signing = input.envelopeSigning;
      const scope = signing?.rotationEnabled
        ? installedIdentityEnvelopeRotationScope({
            subjectAltName: new X509Certificate(signing.transport.certificate).subjectAltName,
            privacyDomainId: input.privacyDomainId,
            environmentId: signing.environmentId,
            callerWorkloadCredentialId: signing.callerWorkloadCredentialId,
            callerWorkloadKeyDigest: signing.transport.callerWorkloadKeyDigest,
          })
        : undefined;
      if (scope && scope.participantId !== input.participantId)
        throw new Error('Installed envelope rotation participant does not match the test scope');
      const activation = signing
        ? {
            environmentId: signing.environmentId,
            callerWorkloadCredentialId: signing.callerWorkloadCredentialId,
            provider: createHttpIdentityEnvelopeSigningProvider(signing.transport),
          }
        : undefined;
      participant = buildPostgresParticipantService(
        input.runtime,
        adapters.authentication,
        adapters.signals,
        adapters.mutationAuthorization,
        createLocalIdentityRuntimeVerifier([await readFile(file('public.der'))]),
        adapters.directoryGroups,
        activation,
      );
      if (activation) participant.addHook('onClose', async () => activation.provider.close());
      if (signing && scope) {
        const provider = createHttpIdentityEnvelopeRotationProvider(signing.transport);
        const rotation = new IdentityEnvelopeRotationRuntime(
          new IdentityEnvelopeRotationWorker(
            new PostgresIdentityEnvelopeRotationAttemptStore(input.runtime, scope),
            provider,
          ),
          provider,
          () => participant!.log.error({ event: 'identity_envelope_rotation_worker_stopped' }),
        );
        participant.addHook('onReady', async () => rotation.start());
        participant.addHook('onClose', async () => rotation.stop());
      }
      return participant.listen({ host: '127.0.0.1', port: 0 });
    };
    let url = await startParticipant();
    return {
      identityUrl,
      directory: root,
      identityDenials: () => [...identityDenials],
      identityInternalToken: internalToken,
      participantUrl: () => url,
      async login(role: 'operator' | 'viewer') {
        const response = await fetch(`${identityUrl}/internal/v1/local/session/login`, {
          method: 'POST',
          headers: {
            'authorization': `Bearer ${internalToken}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ role, credential: internalToken }),
          signal: AbortSignal.timeout(5000),
        });
        if (response.status !== 201)
          throw new Error(`Initial trust login failed: ${response.status}`);
        return (await response.json()) as { sessionToken: string; sessionId: string };
      },
      async get(
        sessionToken: string,
        resourceId: string,
        privacyDomainId = input.privacyDomainId,
        resource:
          | 'envelopes'
          | 'assignments'
          | 'delegations'
          | 'roles'
          | 'role-proposals'
          | 'grant-proposals' = 'assignments',
      ) {
        const response = await fetch(
          `${url}/v1/participants/${input.participantId}/${resource}/${resourceId}`,
          {
            headers: {
              'Authorization': `Bearer ${sessionToken}`,
              'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
            },
            signal: AbortSignal.timeout(5_000),
          },
        );
        return {
          status: response.status,
          cacheControl: response.headers.get('cache-control'),
          body: (await response.json()) as unknown,
        };
      },
      async restartParticipant() {
        await participant!.close();
        url = await startParticipant();
      },
      stopIdentity,
      async configureGovernedInitialEnrollment(profile: unknown) {
        if (!input.localQaFixture) throw new Error('Explicit local QA fixture required');
        const { readGovernedInitialEnrollmentProfile } =
          await import('../../../services/identity-service/src/domain/governed-initial-enrollment-profile.js');
        await writeFile(file('initial-enrollment.json'), JSON.stringify(profile), { mode: 0o600 });
        config = {
          ...config,
          governedInitialEnrollmentProfile: await readGovernedInitialEnrollmentProfile({
            path: file('initial-enrollment.json'),
            localQaEnabled: true,
            origin: new URL(config.IDENTITY_OIDC_REDIRECT_URI).origin,
            issuer: config.IDENTITY_OIDC_ISSUER,
            audience: config.IDENTITY_OIDC_CLIENT_ID,
            participantId: input.participantId,
            privacyDomainId: input.privacyDomainId,
          }),
        };
      },
      async restartIdentity(databasePort?: number) {
        await stopIdentity();
        if (databasePort !== undefined) {
          if (!Number.isInteger(databasePort) || databasePort < 1 || databasePort > 65535)
            throw new Error('Invalid isolated database port');
          config.IDENTITY_DATABASE_PORT = databasePort;
        }
        identity = await buildLocalIdentityRuntime(config, input.directoryProfiles);
        await identity.app.listen({ host: '127.0.0.1', port: Number(new URL(identityUrl).port) });
      },
      close,
    };
  } catch (error) {
    await closeFixtureResources([close], { error });
    throw error;
  }
}
