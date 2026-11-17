import { loadProtectedProofKeys } from './evidence/protected-crypto.js';
import { loadStoreRetirementAdmissionAuthorities } from './evidence/store-retirement-admission.js';
import { FactArtifactsClient } from './configuration/fact-artifacts.js';
import { loadModuleReleaseCatalog } from '../../module-registry/src/module-release-catalog.js';
import { registerPublicModuleMutationRoute } from '../../module-registry/src/public-module-http.js';
import { setTimeout as delay } from 'node:timers/promises';
import { createSigningContinuationClient } from './signing-continuation-client.js';
import { SigningRotationFinalizer } from './signing-rotation-finalizer.js';
import {
  SigningContinuationDenied,
  createSigningContinuationVerifier,
} from '../../identity-service/src/domain/signing-continuation.js';
import { readFile } from 'node:fs/promises';

import Fastify from 'fastify';
import { Pool } from 'pg';
import { z } from 'zod';

import { handleDatabaseIdleErrors } from '../../identity-service/src/db/pool-idle-errors.js';

import { createLocalIdentityRuntimeVerifier } from '../../identity-service/src/domain/identity-runtime-crypto.js';
import { createProviderBusinessReceiptSigner } from '../../identity-service/src/domain/provider-business-receipt-signer.js';
import { createHttpBusinessSigningProvider } from '../../identity-service/src/domain/http-business-signing-provider.js';

import { registerConfigurationRoutes } from './configuration/http.js';
import { NotificationEndpointVerificationState } from './notifications/endpoint-verification-state.js';
import { loadPackagedNotificationDeliveryConsumer } from './notifications/packaged-delivery-runtime.js';
import { loadPackagedNotificationVerificationRuntime } from './notifications/packaged-verification-runtime.js';
import { createLocalConfigurationAuthorizer } from './configuration/local-authorizer.js';
import { registerSigningRotationRoutes } from './signing-http.js';
import {
  loadExplorerTransport,
  registerLivePrivacyExplorer,
} from './privacy-explorer/live-runtime.js';

const configSchema = z.object({
  OPENPC_LOCAL_RUNTIME: z.literal('1'),
  OPENPC_LOCAL_RUNTIME_QA_FIXTURE: z.enum(['0', '1']).default('0'),
  CONTROL_API_MODULE_RELEASE_CATALOG_FILE: z.string().min(1),
  CONTROL_API_MODULE_RELEASE_TRUST_FILE: z.string().min(1),
  CONTROL_API_SIGNING_CONTINUATION_URL: z.url().optional(),
  CONTROL_API_SIGNING_CONTINUATION_CA_FILE: z.string().min(1).optional(),
  CONTROL_API_SIGNING_FINALIZER_ENABLED: z.enum(['0', '1']).default('1'),
  CONTROL_API_LOCAL_PARTICIPANT_ID: z.uuidv7().optional(),
  CONTROL_API_SIGNING_PROVIDER_URL: z.url(),
  CONTROL_API_SIGNING_PROVIDER_CA_FILE: z.string().min(1),
  CONTROL_API_SIGNING_PROVIDER_CERT_FILE: z.string().min(1),
  CONTROL_API_SIGNING_PROVIDER_KEY_FILE: z.string().min(1),
  CONTROL_API_SIGNING_WORKLOAD_CREDENTIAL_ID: z.uuidv7(),
  CONTROL_API_SIGNING_LIFECYCLE_CREDENTIAL_ID: z.uuidv7(),
  CONTROL_API_EVIDENCE_ENVIRONMENT_ID: z.string().min(1).max(160),
  CONTROL_API_DATABASE_HOST: z.string().min(1),
  CONTROL_API_DATABASE_PORT: z.coerce.number().int().min(1).max(65_535),
  CONTROL_API_DATABASE_NAME: z.string().min(1),
  CONTROL_API_DATABASE_USER: z.string().min(1),
  CONTROL_API_DATABASE_PASSWORD_FILE: z.string().min(1),
  CONTROL_API_IDENTITY_URL: z.url(),
  CONTROL_API_EXPLORER_TRANSPORT_FILE: z.string().min(1).optional(),
  CONTROL_API_PROTECTED_PROOF_KEYS_FILE: z.string().min(1).optional(),
  CONTROL_API_STORE_RETIREMENT_ADMISSIONS_FILE: z.string().min(1).optional(),
  CONTROL_API_NOTIFICATION_DELIVERY_FILE: z.string().min(1).optional(),
  CONTROL_API_NOTIFICATION_VERIFICATION_FILE: z.string().min(1).optional(),
  CONTROL_API_FACT_URL: z.url().optional(),
  CONTROL_API_FACT_INTERNAL_TOKEN_FILE: z.string().min(1).optional(),
  CONTROL_API_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES: z.string().min(1),
  CONTROL_API_SIGNING_CONTINUATION_TRUSTED_PUBLIC_KEY_FILES: z.string().min(1).optional(),
  CONTROL_API_IDENTITY_INTERNAL_TOKEN_FILE: z.string().min(1),
  CONTROL_API_LOCAL_PRIVACY_DOMAIN_ID: z.uuid(),
  CONTROL_API_LISTEN: z.string().regex(/^[^:]+:[1-9][0-9]{0,4}$/u),
});

async function secret(path: string): Promise<string> {
  const value = (await readFile(path, 'utf8')).trim();
  if (value.length < 32 || value.length > 256 || !/^\S+$/u.test(value))
    throw new Error('invalid secret');
  return value;
}

async function main() {
  const config = configSchema.parse(process.env);
  const database = {
    host: config.CONTROL_API_DATABASE_HOST,
    port: config.CONTROL_API_DATABASE_PORT,
    database: config.CONTROL_API_DATABASE_NAME,
    user: config.CONTROL_API_DATABASE_USER,
    password: await secret(config.CONTROL_API_DATABASE_PASSWORD_FILE),
  };
  const pool = new Pool({
    ...database,
    options: `-c openpc.local_qa_runtime=${config.OPENPC_LOCAL_RUNTIME_QA_FIXTURE}`,
    max: 8,
  });
  handleDatabaseIdleErrors(pool);
  const app = Fastify({ logger: true });
  let notificationRuntime: Awaited<ReturnType<typeof loadPackagedNotificationVerificationRuntime>>;
  let notificationDelivery: Awaited<ReturnType<typeof loadPackagedNotificationDeliveryConsumer>>;
  let closeSigningProvider: (() => void) | undefined;
  let issuer: ReturnType<typeof createSigningContinuationClient> | undefined;
  let finalizerRun: Promise<void> | undefined;
  const stopping = new AbortController();
  let closing: Promise<void> | undefined;
  const close = () => {
    closing ??= (async () => {
      stopping.abort();
      let failed = false;
      const deliveryStopped = notificationDelivery?.close().catch(() => {
        failed = true;
      });
      // Drain HTTP before closing the feature transport. A failed owner must not
      // prevent cleanup of the remaining independently owned resources.
      for (const stop of [
        () => finalizerRun,
        () => issuer?.close(),
        () => app.close(),
        () => notificationRuntime?.close(),
        () => deliveryStopped,
        () => closeSigningProvider?.(),
        () => pool.end(),
      ]) {
        try {
          await stop();
        } catch {
          failed = true;
        }
      }
      if (failed) throw new Error('Control API runtime cleanup failed');
    })();
    return closing;
  };
  try {
    const signingProvider = createHttpBusinessSigningProvider({
      origin: config.CONTROL_API_SIGNING_PROVIDER_URL,
      trustCa: await readFile(config.CONTROL_API_SIGNING_PROVIDER_CA_FILE),
      certificate: await readFile(config.CONTROL_API_SIGNING_PROVIDER_CERT_FILE),
      privateKey: await readFile(config.CONTROL_API_SIGNING_PROVIDER_KEY_FILE),
    });
    closeSigningProvider = () => signingProvider.close();
    const authorizer = createLocalConfigurationAuthorizer(
      config.CONTROL_API_IDENTITY_URL,
      await secret(config.CONTROL_API_IDENTITY_INTERNAL_TOKEN_FILE),
      config.CONTROL_API_LOCAL_PRIVACY_DOMAIN_ID,
    );
    const identityRuntimeVerifier = createLocalIdentityRuntimeVerifier(
      await Promise.all(
        config.CONTROL_API_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES.split(',').map((path) =>
          readFile(path),
        ),
      ),
    );
    registerSigningRotationRoutes(app, {
      pool,
      identityRuntimeVerifier,
      authorizer,
      provider: signingProvider,
      workloadCredentialId: config.CONTROL_API_SIGNING_WORKLOAD_CREDENTIAL_ID,
      lifecycleWorkloadCredentialId: config.CONTROL_API_SIGNING_LIFECYCLE_CREDENTIAL_ID,
      environmentId: config.CONTROL_API_EVIDENCE_ENVIRONMENT_ID,
    });
    const businessEvidence = {
      environmentId: config.CONTROL_API_EVIDENCE_ENVIRONMENT_ID,
      signer: createProviderBusinessReceiptSigner(
        signingProvider,
        config.CONTROL_API_SIGNING_WORKLOAD_CREDENTIAL_ID,
      ),
    };
    notificationRuntime = await loadPackagedNotificationVerificationRuntime(
      config.CONTROL_API_NOTIFICATION_VERIFICATION_FILE,
      { database, identityRuntimeVerifier, businessEvidence },
    );
    // Notification backlog may remain unavailable without closing independent
    // Control capabilities. This optional package never changes DB /readyz into
    // a claim of current notification native authority.
    try {
      notificationDelivery = await loadPackagedNotificationDeliveryConsumer(
        config.CONTROL_API_NOTIFICATION_DELIVERY_FILE,
        { database },
      );
    } catch {
      app.log.warn({ event: 'notification_consumer_unavailable', code: 'MOUNT_UNAVAILABLE' });
    }
    const moduleCatalog = await loadModuleReleaseCatalog(
      config.CONTROL_API_MODULE_RELEASE_CATALOG_FILE,
      config.CONTROL_API_MODULE_RELEASE_TRUST_FILE,
    );
    registerPublicModuleMutationRoute(app, {
      pool,
      authorizer,
      identityRuntimeVerifier,
      businessEvidence,
      catalog: moduleCatalog,
    });
    if (
      !!config.CONTROL_API_FACT_URL !== !!config.CONTROL_API_FACT_INTERNAL_TOKEN_FILE ||
      (config.CONTROL_API_FACT_URL && !config.CONTROL_API_LOCAL_PARTICIPANT_ID)
    )
      throw new Error('Incomplete Fact service configuration');
    const storeRetirementAdmissions = config.CONTROL_API_STORE_RETIREMENT_ADMISSIONS_FILE
      ? await loadStoreRetirementAdmissionAuthorities(
          config.CONTROL_API_STORE_RETIREMENT_ADMISSIONS_FILE,
        )
      : undefined;
    app.addHook('onClose', async () => {
      for (const authority of storeRetirementAdmissions?.values() ?? []) authority.close();
    });
    registerConfigurationRoutes(app, {
      ...(notificationRuntime
        ? {
            notificationEndpointOwners: notificationRuntime.owners,
            notificationEndpointVerification: notificationRuntime.workflow,
          }
        : {
            notificationEndpointOwners: new NotificationEndpointVerificationState(
              pool,
              identityRuntimeVerifier,
            ),
          }),
      ...(storeRetirementAdmissions ? { storeRetirementAdmissions } : {}),
      ...(config.CONTROL_API_PROTECTED_PROOF_KEYS_FILE
        ? {
            protectedProofKeys: await loadProtectedProofKeys(
              config.CONTROL_API_PROTECTED_PROOF_KEYS_FILE,
            ),
          }
        : {}),
      ...(config.CONTROL_API_FACT_URL
        ? {
            factArtifacts: new FactArtifactsClient(
              config.CONTROL_API_FACT_URL,
              await secret(config.CONTROL_API_FACT_INTERNAL_TOKEN_FILE!),
              {
                participantId: config.CONTROL_API_LOCAL_PARTICIPANT_ID!,
                privacyDomainId: config.CONTROL_API_LOCAL_PRIVACY_DOMAIN_ID,
              },
            ),
          }
        : {}),
      moduleReleaseVerifier: moduleCatalog.verify,
      pool,
      businessEvidence,
      identityRuntimeVerifier,
      authorizer,
    });
    await registerLivePrivacyExplorer(app, {
      pool,
      authorizer,
      identityUrl: config.CONTROL_API_IDENTITY_URL,
      ...(config.CONTROL_API_EXPLORER_TRANSPORT_FILE
        ? {
            transport: await loadExplorerTransport(config.CONTROL_API_EXPLORER_TRANSPORT_FILE),
          }
        : {}),
    });
    app.get('/readyz', async (_request, reply) => {
      try {
        const result = await pool.query<{ readonly tableName: string | null }>(
          'select to_regclass(\'control.provider_profile\')::text as "tableName"',
        );
        return result.rows[0]?.tableName
          ? { status: 'ready' }
          : reply.code(503).send({ status: 'unavailable' });
      } catch {
        return reply.code(503).send({ status: 'unavailable' });
      }
    });
    const [host, port] = config.CONTROL_API_LISTEN.split(':');
    await app.listen({ host, port: Number(port) });
    if (
      config.CONTROL_API_SIGNING_CONTINUATION_URL &&
      config.CONTROL_API_SIGNING_FINALIZER_ENABLED === '1'
    ) {
      if (
        !config.CONTROL_API_SIGNING_CONTINUATION_CA_FILE ||
        !config.CONTROL_API_SIGNING_CONTINUATION_TRUSTED_PUBLIC_KEY_FILES ||
        !config.CONTROL_API_LOCAL_PARTICIPANT_ID
      )
        throw new Error('Incomplete signing finalizer configuration');
      const certificate = await readFile(config.CONTROL_API_SIGNING_PROVIDER_CERT_FILE);
      issuer = createSigningContinuationClient({
        origin: config.CONTROL_API_SIGNING_CONTINUATION_URL,
        ca: await readFile(config.CONTROL_API_SIGNING_CONTINUATION_CA_FILE),
        certificate,
        privateKey: await readFile(config.CONTROL_API_SIGNING_PROVIDER_KEY_FILE),
      });
      const finalizer = new SigningRotationFinalizer({
        pool,
        provider: signingProvider,
        issuer,
        participantId: config.CONTROL_API_LOCAL_PARTICIPANT_ID,
        privacyDomainId: config.CONTROL_API_LOCAL_PRIVACY_DOMAIN_ID,
        workloadCredentialId: config.CONTROL_API_SIGNING_WORKLOAD_CREDENTIAL_ID,
        certificate,
        verify: createSigningContinuationVerifier(
          await Promise.all(
            config.CONTROL_API_SIGNING_CONTINUATION_TRUSTED_PUBLIC_KEY_FILES.split(',').map(
              (path) => readFile(path),
            ),
          ),
        ),
      });
      finalizerRun = (async () => {
        while (!stopping.signal.aborted) {
          try {
            await finalizer.tick();
          } catch (error) {
            if (!(error instanceof SigningContinuationDenied))
              app.log.warn({
                event: 'signing_continuation_retry',
                code:
                  typeof error === 'object' &&
                  error !== null &&
                  'code' in error &&
                  typeof error.code === 'string' &&
                  /^[A-Z0-9]{5}$/u.test(error.code)
                    ? error.code
                    : 'UNAVAILABLE',
              });
          }
          await delay(250, undefined, { signal: stopping.signal }).catch(() => {});
        }
      })();
    }
    const shutdown = () => {
      void close().catch(() => {
        process.stderr.write('{"level":"error","event":"control_api_cleanup_failed"}\n');
        process.exitCode = 1;
      });
    };
    process.once('SIGTERM', shutdown);
    process.once('SIGINT', shutdown);
    try {
      await notificationDelivery?.start();
    } catch {
      app.log.warn({ event: 'notification_consumer_unavailable', code: 'TRANSPORT_UNAVAILABLE' });
      try {
        await notificationDelivery?.close();
        notificationDelivery = undefined;
      } catch {
        app.log.error({ event: 'notification_consumer_cleanup_failed' });
      }
    }
  } catch (error) {
    await close();
    throw error;
  }
}

void main().catch((error: unknown) => {
  const code =
    error !== null &&
    typeof error === 'object' &&
    'code' in error &&
    typeof error.code === 'string' &&
    /^[A-Z][A-Z0-9_-]{0,80}$/u.test(error.code)
      ? error.code
      : 'STARTUP_FAILED';
  const configurationFields =
    error instanceof z.ZodError ? error.issues.map((issue) => issue.path.join('.')) : undefined;
  process.stderr.write(
    `${JSON.stringify({ level: 'error', event: 'control_api_runtime_stopped', boundary: 'startup', code, configurationFields })}\n`,
  );
  process.exitCode = 1;
});
