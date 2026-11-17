import { localQaDurationMultiplier } from '../../../packages/security-kernel/src/local-qa-duration-profile.js';
import { defaultDiscoveryCertificateIssuancePolicy } from './domain/discovery-certificate-issuance-policy.js';
import { createQualificationObserverClient } from './domain/qualification-observer-client.js';
import { SigningContinuationIssuer } from './db/signing-continuation-store.js';
import {
  availableSessionPrivacyContexts,
  sessionPrivacyContext,
} from './domain/session-privacy-context.js';
import {
  createSigningContinuationSigner,
  createSigningContinuationVerifier,
} from './domain/signing-continuation.js';
import { buildSigningContinuationMtlsService } from './domain/signing-continuation-mtls.js';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';

import { Pool } from 'pg';
import { z } from 'zod';

import { handleDatabaseIdleErrors } from './db/pool-idle-errors.js';

import { buildIdentityService, type WebAuthnAllowedOriginResolver } from './app.js';
import {
  DirectoryProfileRegistry,
  createRegisteredDirectoryProfiles,
  directoryProfileDefinitionsSchema,
  type DirectoryProfileDefinitions,
} from './domain/directory-profiles.js';
import {
  IdentityKernelError,
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from './domain/identity-kernel.js';
import { createLocalIdentityRuntimeCryptoAdapter } from './domain/identity-runtime-crypto.js';
import { RuntimeSnapshotPublisher } from './domain/runtime-snapshot-publisher.js';
import { authorizeLocalConfigurationMutation } from './domain/local-configuration-authorization.js';
import { createLocalIdentityAuthorizationAdapter } from './domain/local-identity-authorization.js';
import { buildLocalWorkloadMtlsService } from './domain/local-workload-mtls.js';
import { createLocalWebAuthnTrustAdapter } from './domain/local-webauthn-trust-adapter.js';
import { createWebAuthnRegistrationAdapter } from './domain/webauthn-registration.js';
import { readGovernedInitialEnrollmentProfile } from './domain/governed-initial-enrollment-profile.js';
import type { GovernedInitialEnrollmentProfile } from './domain/governed-initial-enrollment.js';
import {
  hardwareAttestationProfileSchema,
  type HardwareAttestationProfile,
} from './domain/hardware-attestation.js';
import {
  createHttpWorkloadCredentialIssuer,
  authenticateHistoricalLocalWorkloadIssuerProfile,
} from './domain/workload-credential-issuer.js';
import { loadWorkloadRenewalPolicyRuntime } from './domain/workload-renewal-policy-runtime.js';
import { stageMutationCandidateInTransaction } from './db/mutation-candidate-store.js';
import { runScopedTransaction } from './db/scoped-transaction.js';
import { localOperationId } from './domain/local-operation-id.js';
import {
  authorizeLocalPolicyAction,
  type PolicyAuthorizationContext,
} from './domain/policy-authorization.js';
import { createHttpOidcTrustAdapter } from './domain/http-oidc-trust-adapter.js';

import { readRecoveryLifetimes } from './domain/platform-recovery-lifetimes.js';
import { discoveryApprovalResumePurpose } from './contracts/discovery-certificate-recovery.js';

const runtimeSchema = z.object({
  OPENPC_LOCAL_RUNTIME: z.literal('1'),
  OPENPC_LOCAL_RUNTIME_QA_FIXTURE: z.enum(['0', '1']).default('0'),
  // Optional observer failures are contained by their own transport owner.
  IDENTITY_QUALIFICATION_OBSERVER_FILE: z.string().optional(),
  IDENTITY_DATABASE_HOST: z.string().min(1),
  IDENTITY_DATABASE_PORT: z.coerce.number().int().min(1).max(65_535),
  IDENTITY_DATABASE_NAME: z.string().regex(/^[a-z][a-z0-9_]*$/u),
  IDENTITY_DATABASE_USER: z.string().regex(/^[a-z][a-z0-9_]*$/u),
  IDENTITY_DATABASE_PASSWORD_FILE: z.string().min(1),
  IDENTITY_WORKLOAD_RENEWAL_POLICY_FILE: z.string().min(1).optional(),
  IDENTITY_INTERNAL_TOKEN_FILE: z.string().min(1),
  IDENTITY_RUNTIME_SIGNING_PRIVATE_KEY_FILE: z.string().min(1),
  IDENTITY_RUNTIME_SIGNING_PUBLIC_KEY_FILE: z.string().min(1),
  IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES: z
    .string()
    .min(1)
    .refine((value) => value.split(',').every((path) => path.length > 0)),
  IDENTITY_LOCAL_OPERATOR_CREDENTIAL_FILE: z.string().min(1),
  IDENTITY_LOCAL_VIEWER_CREDENTIAL_FILE: z.string().min(1),
  IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID: z.uuid(),
  IDENTITY_LOCAL_VIEWER_PRINCIPAL_ID: z.uuid(),
  IDENTITY_LOCAL_PARTICIPANT_ID: z.uuid(),
  IDENTITY_LOCAL_PRIVACY_DOMAIN_ID: z.uuid(),
  IDENTITY_OIDC_ISSUER: z.url(),
  IDENTITY_OIDC_CLIENT_ID: z.string().min(1),
  IDENTITY_OIDC_REDIRECT_URI: z.url(),
  OPENPC_LOCAL_QA_DURATION_PROFILE: z.literal('LOCAL_QA_10X').optional(),
  IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS: z.coerce.number().int().optional(),
  IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS: z.coerce
    .number()
    .int()
    .min(60_000)
    .max(36_000_000)
    .optional(),
  IDENTITY_DISCOVERY_ISSUANCE_ATTEMPT_TTL_MS: z.coerce
    .number()
    .int()
    .positive()
    .max(300_000)
    .optional(),
  IDENTITY_DISCOVERY_ISSUANCE_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).optional(),
  IDENTITY_RECOVERY_LEASE_TTL_MS: z.coerce.number().int().positive().max(172_800_000).optional(),
  IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS: z.coerce
    .number()
    .int()
    .positive()
    .max(86_400_000)
    .optional(),
  IDENTITY_RECOVERY_ATTESTATION_PROFILE_FILE: z.string().min(1).optional(),
  IDENTITY_GOVERNED_INITIAL_ENROLLMENT_PROFILE_FILE: z.string().min(1).optional(),
  IDENTITY_DIRECTORY_PROFILES_FILE: z.string().min(1).optional(),
  IDENTITY_SIGNING_CONTINUATION_CLIENT_CA_FILE: z.string().min(1).optional(),
  IDENTITY_SIGNING_CONTINUATION_PRIVATE_KEY_FILE: z.string().min(1).optional(),
  IDENTITY_SIGNING_CONTINUATION_PUBLIC_KEY_FILE: z.string().min(1).optional(),
  IDENTITY_SIGNING_CONTINUATION_TRUSTED_PUBLIC_KEY_FILES: z.string().min(1).optional(),
  IDENTITY_SIGNING_CONTINUATION_LISTEN: z
    .string()
    .regex(/^[^:]+:[1-9][0-9]{0,4}$/u)
    .refine((value) => Number(value.split(':').at(-1)) <= 65535)
    .optional(),
  IDENTITY_MTLS_CA_FILE: z.string().min(1),
  IDENTITY_WORKLOAD_ISSUER_URL: z.url(),
  IDENTITY_WORKLOAD_ISSUER_TOKEN_FILE: z.string().min(1),
  IDENTITY_WORKLOAD_ISSUER_CA_FILE: z.string().min(1).optional(),
  IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_FILE: z.string().min(1).optional(),
  IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_SHA256: z
    .string()
    .regex(/^[0-9a-f]{64}$/u)
    .optional(),
  IDENTITY_MTLS_SERVER_CERT_FILE: z.string().min(1),
  IDENTITY_MTLS_SERVER_KEY_FILE: z.string().min(1),
  IDENTITY_MTLS_LISTEN: z
    .string()
    .regex(/^[^:]+:[1-9][0-9]{0,4}$/u)
    .refine((value) => Number(value.split(':').at(-1)) <= 65_535),
  IDENTITY_LISTEN: z
    .string()
    .regex(/^[^:]+:[1-9][0-9]{0,4}$/u)
    .refine((value) => Number(value.split(':').at(-1)) <= 65_535),
});

export interface LocalIdentityRuntimeConfig extends z.infer<typeof runtimeSchema> {
  readonly internalToken: string;
  readonly operatorCredential: string;
  readonly viewerCredential: string;
  readonly databasePassword: string;
  readonly identityRuntimePrivateKey: Buffer;
  readonly identityRuntimePublicKey: Buffer;
  readonly identityRuntimeTrustedPublicKeys: readonly Buffer[];
  readonly workloadIssuerToken: string;
  readonly recoveryAttestationProfile?: HardwareAttestationProfile;
  readonly governedInitialEnrollmentProfile?: GovernedInitialEnrollmentProfile;
  readonly directoryProfileDefinitions?: DirectoryProfileDefinitions;
}

async function secret(path: string): Promise<string> {
  const value = (await readFile(path, 'utf8')).trim();
  if (value.length < 32 || value.length > 256 || !/^\S+$/u.test(value)) {
    throw new Error('invalid local identity secret');
  }
  return value;
}

export async function readLocalIdentityRuntimeConfig(
  environment: NodeJS.ProcessEnv,
): Promise<LocalIdentityRuntimeConfig> {
  for (const key of Object.keys(environment)) {
    if (key.startsWith('IDENTITY_') && !(key in runtimeSchema.shape)) {
      throw new Error(`unknown local identity variable: ${key}`);
    }
  }
  const parsed = runtimeSchema.parse(environment);
  readRecoveryLifetimes(parsed);
  if (
    Boolean(parsed.IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_FILE) !==
      Boolean(parsed.IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_SHA256) ||
    (parsed.IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_FILE &&
      (parsed.OPENPC_LOCAL_RUNTIME_QA_FIXTURE !== '1' || !parsed.IDENTITY_WORKLOAD_ISSUER_CA_FILE))
  )
    throw new Error('Incomplete or non-QA local issuer profile configuration');
  if (
    parsed.IDENTITY_GOVERNED_INITIAL_ENROLLMENT_PROFILE_FILE &&
    !parsed.IDENTITY_RECOVERY_ATTESTATION_PROFILE_FILE
  )
    throw new Error('Governed executor enrollment requires configured hardware-attestation trust');
  if (
    parsed.IDENTITY_GOVERNED_INITIAL_ENROLLMENT_PROFILE_FILE &&
    !parsed.IDENTITY_RECOVERY_ATTESTATION_PROFILE_FILE
  )
    throw new Error('Governed executor enrollment requires configured hardware-attestation trust');
  const durationMultiplier = localQaDurationMultiplier(parsed);
  if (
    durationMultiplier === 1 &&
    (parsed.IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS ?? 0) > 3_600_000
  )
    throw new Error('Snapshot lifetime requires temporary local QA profile');
  if (
    parsed.IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS !== undefined &&
    parsed.IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS !== 24 * 60 * 60 * 1000
  )
    throw new Error('Invalid local QA session timeout');
  if (
    parsed.IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS !== undefined &&
    parsed.IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS > 60_000 &&
    parsed.OPENPC_LOCAL_RUNTIME_QA_FIXTURE !== '1'
  )
    throw new Error('Runtime snapshot lifetime requires local QA fixture');
  const continuation = [
    parsed.IDENTITY_SIGNING_CONTINUATION_CLIENT_CA_FILE,
    parsed.IDENTITY_SIGNING_CONTINUATION_LISTEN,
    parsed.IDENTITY_SIGNING_CONTINUATION_PRIVATE_KEY_FILE,
    parsed.IDENTITY_SIGNING_CONTINUATION_PUBLIC_KEY_FILE,
    parsed.IDENTITY_SIGNING_CONTINUATION_TRUSTED_PUBLIC_KEY_FILES,
  ];
  if (continuation.some(Boolean) && !continuation.every(Boolean))
    throw new Error('Incomplete signing continuation listener configuration');
  const trustedPublicKeyPaths = parsed.IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES.split(',');
  return {
    ...parsed,
    ...(parsed.IDENTITY_DIRECTORY_PROFILES_FILE === undefined
      ? {}
      : {
          directoryProfileDefinitions: directoryProfileDefinitionsSchema.parse(
            JSON.parse(await readFile(parsed.IDENTITY_DIRECTORY_PROFILES_FILE, 'utf8')),
          ),
        }),
    ...(parsed.IDENTITY_RECOVERY_ATTESTATION_PROFILE_FILE === undefined
      ? {}
      : {
          recoveryAttestationProfile: hardwareAttestationProfileSchema.parse(
            JSON.parse(await readFile(parsed.IDENTITY_RECOVERY_ATTESTATION_PROFILE_FILE, 'utf8')),
          ),
        }),
    governedInitialEnrollmentProfile: await readGovernedInitialEnrollmentProfile({
      path: parsed.IDENTITY_GOVERNED_INITIAL_ENROLLMENT_PROFILE_FILE,
      localQaEnabled: parsed.OPENPC_LOCAL_RUNTIME_QA_FIXTURE === '1',
      origin: new URL(parsed.IDENTITY_OIDC_REDIRECT_URI).origin,
      issuer: parsed.IDENTITY_OIDC_ISSUER,
      audience: parsed.IDENTITY_OIDC_CLIENT_ID,
      participantId: parsed.IDENTITY_LOCAL_PARTICIPANT_ID,
      privacyDomainId: parsed.IDENTITY_LOCAL_PRIVACY_DOMAIN_ID,
    }),
    internalToken: await secret(parsed.IDENTITY_INTERNAL_TOKEN_FILE),
    operatorCredential: await secret(parsed.IDENTITY_LOCAL_OPERATOR_CREDENTIAL_FILE),
    viewerCredential: await secret(parsed.IDENTITY_LOCAL_VIEWER_CREDENTIAL_FILE),
    databasePassword: await secret(parsed.IDENTITY_DATABASE_PASSWORD_FILE),
    identityRuntimePrivateKey: await readFile(parsed.IDENTITY_RUNTIME_SIGNING_PRIVATE_KEY_FILE),
    identityRuntimePublicKey: await readFile(parsed.IDENTITY_RUNTIME_SIGNING_PUBLIC_KEY_FILE),
    identityRuntimeTrustedPublicKeys: await Promise.all(
      trustedPublicKeyPaths.map((path) => readFile(path)),
    ),
    workloadIssuerToken: await secret(parsed.IDENTITY_WORKLOAD_ISSUER_TOKEN_FILE),
  };
}

/** The issuer's verification anchor can be installed independently of transport trust. */
export async function readLocalWorkloadIssuerCa(
  config: LocalIdentityRuntimeConfig,
): Promise<Buffer> {
  return readFile(config.IDENTITY_WORKLOAD_ISSUER_CA_FILE ?? config.IDENTITY_MTLS_CA_FILE);
}

export async function readLocalWorkloadIssuerProfile(
  config: LocalIdentityRuntimeConfig,
  trustedCaPem: Buffer,
) {
  if (!config.IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_FILE) return undefined;
  return authenticateHistoricalLocalWorkloadIssuerProfile({
    bytes: await readFile(config.IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_FILE),
    expectedDigest: config.IDENTITY_WORKLOAD_ISSUER_LOCAL_PROFILE_SHA256!,
    endpoint: config.IDENTITY_WORKLOAD_ISSUER_URL,
    trustedCaPem,
    localQaEnabled:
      config.OPENPC_LOCAL_RUNTIME === '1' && config.OPENPC_LOCAL_RUNTIME_QA_FIXTURE === '1',
  });
}

/** Reconciliation JWT trust is independent of primary runtime COSE trust. */
export async function readLocalSigningContinuationCrypto(config: LocalIdentityRuntimeConfig) {
  if (!config.IDENTITY_SIGNING_CONTINUATION_LISTEN) return undefined;
  return {
    sign: createSigningContinuationSigner(
      await readFile(config.IDENTITY_SIGNING_CONTINUATION_PRIVATE_KEY_FILE!),
      await readFile(config.IDENTITY_SIGNING_CONTINUATION_PUBLIC_KEY_FILE!),
    ),
    verify: createSigningContinuationVerifier(
      await Promise.all(
        config
          .IDENTITY_SIGNING_CONTINUATION_TRUSTED_PUBLIC_KEY_FILES!.split(',')
          .map((path) => readFile(path)),
      ),
    ),
  };
}

function equalSecret(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function authorized(header: string | undefined, token: string): boolean {
  return header !== undefined && equalSecret(header, `Bearer ${token}`);
}

export function localWebAuthnAllowedOrigin(
  internalToken: string,
  configuredRedirectUri: string,
): WebAuthnAllowedOriginResolver {
  const configuredOrigin = new URL(configuredRedirectUri).origin;
  return (headers) => {
    const claimedOrigin = headers['x-openpc-browser-origin'];
    const attempted = headers.authorization !== undefined || claimedOrigin !== undefined;
    if (!attempted) return undefined;
    return authorized(
      typeof headers.authorization === 'string' ? headers.authorization : undefined,
      internalToken,
    ) &&
      typeof claimedOrigin === 'string' &&
      claimedOrigin === configuredOrigin
      ? configuredOrigin
      : null;
  };
}

export function localPolicyAuthorizationResponse(context: PolicyAuthorizationContext) {
  return {
    sessionId: context.sessionId,
    sessionEpoch: context.sessionEpoch,
    participantId: context.participantId,
    principalId: context.principalId,
    participantEpoch: context.participantEpoch,
    principalEpoch: context.principalEpoch,
    assignmentId: context.assignmentId,
    ...(context.roleId === null || context.roleId === undefined
      ? {}
      : { roleIds: [context.roleId] }),
    assignmentRowVersion: context.assignmentRowVersion,
    authorityEnvelopeId: context.authorityEnvelopeId,
    authorityEpoch: context.authorityEpoch,
    delegationEpoch: context.delegationEpoch,
  };
}

function localSessionDenial(error: unknown): boolean {
  return (
    error instanceof IdentityKernelError &&
    [
      'PC-AUTH-0002',
      'PC-AUTH-0003',
      'PC-AUTH-0005',
      'PC-IDENTITY-1001',
      'PC-IDENTITY-1002',
      'PC-IDENTITY-1005',
    ].includes(error.code)
  );
}

export async function buildLocalIdentityRuntime(
  config: LocalIdentityRuntimeConfig,
  directoryProfiles?: DirectoryProfileRegistry,
) {
  const registeredDirectoryProfiles =
    directoryProfiles ??
    (await createRegisteredDirectoryProfiles(
      config.directoryProfileDefinitions ?? [],
      async (reference) => {
        const match = /^secret:\/\/local\/([a-z][a-z0-9_-]{0,95})#1$/u.exec(reference);
        if (!match) throw new Error('Unregistered local directory secret reference');
        const path = `/run/secrets/${match[1]}`;
        if ((await stat(path)).size > 65536) throw new Error('Invalid local directory secret');
        return readFile(path);
      },
      { localOidcIssuer: config.IDENTITY_OIDC_ISSUER },
    ));
  const pool = new Pool({
    host: config.IDENTITY_DATABASE_HOST,
    port: config.IDENTITY_DATABASE_PORT,
    database: config.IDENTITY_DATABASE_NAME,
    user: config.IDENTITY_DATABASE_USER,
    password: config.databasePassword,
    options: `-c openpc.local_qa_runtime=${config.OPENPC_LOCAL_RUNTIME_QA_FIXTURE} -c openpc.local_qa_duration_profile=${config.OPENPC_LOCAL_QA_DURATION_PROFILE ?? 'NORMAL'}`,
    max: 4,
  });
  handleDatabaseIdleErrors(pool);
  const identityRuntimeCrypto = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: config.identityRuntimePrivateKey,
    activePublicKeySpkiDer: config.identityRuntimePublicKey,
    trustedPublicKeysSpkiDer: config.identityRuntimeTrustedPublicKeys,
  });
  const workloadMtlsCa = await readFile(config.IDENTITY_MTLS_CA_FILE);
  const workloadIssuerCa = await readLocalWorkloadIssuerCa(config);
  const immutableIssuerManifest = await readLocalWorkloadIssuerProfile(config, workloadIssuerCa);
  const workloadTrustDigest = createHash('sha256').update(workloadMtlsCa).digest('hex');
  const runtimeSnapshotPublisher = new RuntimeSnapshotPublisher(
    identityRuntimeCrypto,
    {
      profileId: 'pc.identity.r1.workload-mtls',
      profileVersion: 1n,
      applicability: [1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1],
      profileClass: 1,
      signerId: `sha256:${identityRuntimeCrypto.activeKeyDigest().toString('hex')}`,
    },
    {
      scope: ['pc.identity.r1.workload-mtls', `sha256:${workloadTrustDigest}`, 'TLS1.3-X509'],
      state: {
        caDigest: workloadTrustDigest,
        minimumTlsVersion: 'TLS1.3',
        maximumTlsVersion: 'TLS1.3',
      },
    },
    config.IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS ?? 60_000,
  );
  const recoveryLifetimes = readRecoveryLifetimes(config);
  process.stdout.write(
    `${JSON.stringify({ boundary: 'platform_recovery', stage: 'lifetime_configuration', ...recoveryLifetimes })}\n`,
  );
  const kernel = new IdentityKernel(
    new PostgresIdentityRepository(
      pool,
      systemClock,
      identityRuntimeCrypto,
      runtimeSnapshotPublisher,
      localQaDurationMultiplier(config) === 10
        ? { durationProfile: 'LOCAL_QA_10X', idleMs: 18_000_000, absoluteMs: 432_000_000 }
        : config.IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS === undefined
          ? undefined
          : {
              durationProfile: 'LOCAL_QA',
              idleMs: config.IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS,
              absoluteMs: config.IDENTITY_LOCAL_QA_SESSION_TIMEOUT_MS,
            },
      config.OPENPC_LOCAL_RUNTIME_QA_FIXTURE === '1',
      recoveryLifetimes,
      {
        attemptMs:
          config.IDENTITY_DISCOVERY_ISSUANCE_ATTEMPT_TTL_MS ??
          defaultDiscoveryCertificateIssuancePolicy.attemptMs,
        maximumAttempts:
          config.IDENTITY_DISCOVERY_ISSUANCE_MAX_ATTEMPTS ??
          defaultDiscoveryCertificateIssuancePolicy.maximumAttempts,
      },
      config.governedInitialEnrollmentProfile,
    ),
  );
  const webAuthnTrust = createLocalWebAuthnTrustAdapter(pool, config.IDENTITY_LOCAL_PARTICIPANT_ID);
  const renewalPolicyRuntime = await loadWorkloadRenewalPolicyRuntime(
    config.IDENTITY_WORKLOAD_RENEWAL_POLICY_FILE,
    {
      pool,
      identityOrigin: `http://127.0.0.1:${config.IDENTITY_LISTEN.split(':')[1]}`,
      internalToken: config.internalToken,
      defaultPrivacyDomainId: config.IDENTITY_LOCAL_PRIVACY_DOMAIN_ID,
    },
  );
  const app = buildIdentityService(
    kernel,
    createHttpOidcTrustAdapter(webAuthnTrust, { allowInsecureHttp: true }),
    {
      issuer: config.IDENTITY_OIDC_ISSUER,
      clientId: config.IDENTITY_OIDC_CLIENT_ID,
      redirectUri: config.IDENTITY_OIDC_REDIRECT_URI,
    },
    createLocalIdentityAuthorizationAdapter(
      pool,
      kernel,
      config.IDENTITY_LOCAL_PRIVACY_DOMAIN_ID,
      identityRuntimeCrypto,
    ),
    localWebAuthnAllowedOrigin(config.internalToken, config.IDENTITY_OIDC_REDIRECT_URI),
    createWebAuthnRegistrationAdapter(config.recoveryAttestationProfile),
    createHttpWorkloadCredentialIssuer({
      endpoint: config.IDENTITY_WORKLOAD_ISSUER_URL,
      authorizationToken: config.workloadIssuerToken,
      trustedCaPem: workloadIssuerCa,
      ...(immutableIssuerManifest ? { immutableLocalManifest: immutableIssuerManifest } : {}),
      allowInsecureHttp: true,
    }),
    {
      stage: (context, receiving) =>
        runScopedTransaction(
          pool,
          {
            participantId: context.participantId,
            privacyDomainId: context.privacyDomainId,
            actionIntentId: context.actionIntentId,
            ...(context.catalogOperationId === 'ID-OP-WORKLOAD-ROTATE'
              ? { isolation: 'SERIALIZABLE' as const }
              : {}),
          },
          localOperationId,
          (client) =>
            stageMutationCandidateInTransaction(
              client,
              context,
              {},
              receiving ? { ...receiving, verifier: identityRuntimeCrypto } : undefined,
            ),
        ),
    },
    registeredDirectoryProfiles,
    renewalPolicyRuntime?.api,
  );
  if (renewalPolicyRuntime) app.addHook('onClose', async () => renewalPolicyRuntime.close());
  if (directoryProfiles === undefined)
    app.addHook('onClose', async () => registeredDirectoryProfiles.close());

  app.get('/readyz', async (_request, reply) => {
    try {
      const result = await pool.query<{ present: string | null }>(
        "select to_regclass('control.session')::text present",
      );
      return result.rows[0]?.present
        ? { status: 'ready' as const }
        : reply.code(503).send({ status: 'unavailable' as const });
    } catch {
      return reply.code(503).send({ status: 'unavailable' as const });
    }
  });

  app.post('/internal/v1/local/session/login', async (request, reply) => {
    if (!authorized(request.headers.authorization, config.internalToken)) {
      return reply.code(403).send({ code: 'PC-AUTH-0005' });
    }
    const body = z
      .strictObject({ role: z.enum(['operator', 'viewer']), credential: z.string().min(1) })
      .safeParse(request.body);
    if (!body.success) return reply.code(401).send({ code: 'PC-AUTH-0005' });
    const expected =
      body.data.role === 'operator' ? config.operatorCredential : config.viewerCredential;
    if (!equalSecret(body.data.credential, expected)) {
      return reply.code(401).send({ code: 'PC-AUTH-0005' });
    }
    const principalId =
      body.data.role === 'operator'
        ? config.IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID
        : config.IDENTITY_LOCAL_VIEWER_PRINCIPAL_ID;
    try {
      const session = await kernel.issueLocalDevelopmentSession(
        config.IDENTITY_LOCAL_PARTICIPANT_ID,
        principalId,
        body.data.role === 'operator',
      );
      return reply.code(201).send({
        sessionToken: session.sessionToken,
        role: body.data.role,
        sessionId: session.sessionId,
        principalId: session.principalId,
        participantId: session.participantId,
        contextMode: session.contextMode,
        privacyDomainId: session.privacyDomainId,
        contextEpoch: session.contextEpoch,
        stepUpVerifiedAt: session.stepUpVerifiedAt?.toISOString() ?? null,
      });
    } catch {
      return reply.code(401).send({ code: 'PC-AUTH-0005' });
    }
  });

  app.post('/internal/v1/local/session/validate', async (request, reply) => {
    if (!authorized(request.headers.authorization, config.internalToken)) {
      return reply.code(403).send({ code: 'PC-AUTH-0005' });
    }
    const body = z.strictObject({ sessionToken: z.string().min(1) }).safeParse(request.body);
    if (!body.success) return reply.code(401).send({ code: 'PC-AUTH-0005' });
    try {
      const session = await kernel.sessionSnapshot(body.data.sessionToken);
      const role =
        session.principalId === config.IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID ? 'operator' : 'viewer'; // Presentation only; every owner still checks actual scoped authority.
      const privacyDomainId = await sessionPrivacyContext(pool, kernel, body.data.sessionToken);
      const authority =
        session.contextMode === 'PARTICIPANT'
          ? await authorizeLocalPolicyAction(pool, kernel, {
              sessionToken: body.data.sessionToken,
              privacyDomainId,
              actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
              resourceId: session.principalId,
              stepUpRequired: false,
            })
          : await authorizeLocalPolicyAction(pool, kernel, {
              sessionToken: body.data.sessionToken,
              privacyDomainId,
              actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
              resourceId: session.principalId,
              stepUpRequired: false,
            }).catch((error: unknown) => {
              if (localSessionDenial(error)) return undefined;
              throw error;
            });
      return {
        role,
        platformBootstrapEligible: session.contextMode === 'PLATFORM' && authority !== undefined,
        availableContexts: await availableSessionPrivacyContexts(
          pool,
          kernel,
          body.data.sessionToken,
        ),
        sessionId: session.sessionId,
        sessionEpoch: session.sessionEpoch,
        participantId: session.participantId,
        principalId: session.principalId,
        participantEpoch: session.participantEpoch,
        authorityEpoch: session.authorityEpoch,
        contextMode: session.contextMode,
        ...(session.privacyDomainId === undefined
          ? {}
          : { privacyDomainId: session.privacyDomainId }),
        contextEpoch: session.contextEpoch,
        ...(authority === undefined ? {} : localPolicyAuthorizationResponse(authority)),
        stepUpVerifiedAt: session.stepUpVerifiedAt?.toISOString() ?? null,
      };
    } catch (error) {
      return localSessionDenial(error)
        ? reply.code(401).send({ code: 'PC-AUTH-0005' })
        : reply.code(503).send({ code: 'PC-INTEGRATION-5001' });
    }
  });

  app.post('/internal/v1/local/session/mutation-version', async (request, reply) => {
    if (!authorized(request.headers.authorization, config.internalToken)) {
      return reply.code(403).send({ code: 'PC-AUTH-0005' });
    }
    const body = z.strictObject({ sessionToken: z.string().min(1) }).safeParse(request.body);
    if (!body.success) return reply.code(401).send({ code: 'PC-AUTH-0005' });
    try {
      const [revision, actionIntentDigest] = await Promise.all([
        kernel.sessionAggregateVersion(body.data.sessionToken),
        kernel.actionIntentSemanticDigest(body.data.sessionToken, 'ACT-IDENTITY_UPDATE_STEP_UP-V1'),
      ]);
      return { revision, actionIntentDigest };
    } catch {
      return reply.code(401).send({ code: 'PC-AUTH-0005' });
    }
  });

  app.post('/internal/v1/local/session/command-context', async (request, reply) => {
    if (!authorized(request.headers.authorization, config.internalToken)) {
      return reply.code(403).send({ code: 'PC-AUTH-0005' });
    }
    const body = z
      .strictObject({
        sessionToken: z.string().min(1),
        privacyDomainId: z.uuid().optional(),
        actionIntentId: z.enum([
          'ACT-IDENTITY_CREATE_SESSION-V1',
          'ACT-IDENTITY_DELETE_SESSION-V1',
        ]),
        catalogOperationId: z.enum(['ID-OP-SESSION-REFRESH', 'ID-OP-SESSION-REVOKE']),
        idempotencyKey: z.string().min(16).max(128),
        candidateDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
        origin: z.url(),
        host: z.string().min(1).max(255),
      })
      .safeParse(request.body);
    if (!body.success) return reply.code(422).send({ code: 'PC-IDENTITY-1004' });
    try {
      const context = await kernel.sessionMutationContext(body.data);
      const role =
        context.principalId === config.IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID ? 'operator' : 'viewer';
      return {
        revision: context.expectedRevision,
        actionIntentDigest: context.actionIntentDigest,
        participantId: context.participantId,
        privacyDomainId: context.privacyDomainId,
        role,
        replay: context.replay,
        ...(context.replayCsrfToken === undefined
          ? {}
          : { replayCsrfToken: context.replayCsrfToken }),
      };
    } catch (error) {
      process.stderr.write(
        `OPENPC_SESSION_COMMAND_CONTEXT_FAILURE|error_code=${error instanceof IdentityKernelError ? error.code : 'UNCLASSIFIED'}|error_name=${error instanceof Error ? error.name : 'UnknownError'}\n`,
      );
      return reply.code(401).send({ code: 'PC-AUTH-0005' });
    }
  });

  app.post('/internal/v1/local/policy/authorize', async (request, reply) => {
    if (!authorized(request.headers.authorization, config.internalToken)) {
      return reply.code(403).send({ code: 'PC-AUTH-0005' });
    }
    const body = z
      .strictObject({
        sessionToken: z.string().min(1),
        privacyDomainId: z.uuid(),
        actionIntentId: z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u),
        catalogOperationId: z
          .string()
          .regex(/^[A-Z][A-Z0-9-]+$/u)
          .optional(),
        resourceId: z.string().min(1).max(512),
        stepUpRequired: z.boolean(),
        approvalCandidateDigest: z
          .string()
          .regex(/^sha256:[0-9a-f]{64}$/u)
          .optional(),
        approvalResume: discoveryApprovalResumePurpose.optional(),
        proposedMutation: z
          .strictObject({
            candidate: z.unknown(),
            expectedRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
          })
          .optional(),
        csrfToken: z.string().min(32).max(256).optional(),
        origin: z.url().optional(),
        host: z.string().min(1).max(255).optional(),
      })
      .safeParse(request.body);
    if (!body.success) return reply.code(422).send({ code: 'PC-IDENTITY-1004' });
    try {
      const mutationFields = [body.data.csrfToken, body.data.origin, body.data.host];
      if (mutationFields.some((value) => value !== undefined)) {
        if (mutationFields.some((value) => value === undefined)) {
          return reply.code(422).send({ code: 'PC-IDENTITY-1004' });
        }
        await kernel.verifyCsrf(
          body.data.sessionToken,
          body.data.actionIntentId,
          body.data.origin!,
          body.data.host!,
          body.data.csrfToken!,
        );
      }
      return localPolicyAuthorizationResponse(
        await authorizeLocalPolicyAction(pool, kernel, body.data),
      );
    } catch (error) {
      const code =
        error instanceof Error && 'code' in error ? String(error.code) : 'PC-IDENTITY-1002';
      process.stderr.write(
        `${JSON.stringify({
          boundary: 'local_policy_authorization',
          stage: 'current_authority',
          actionIntentId: body.data.actionIntentId,
          catalogOperationId: body.data.catalogOperationId,
          resourceId: z.uuid().safeParse(body.data.resourceId).success
            ? body.data.resourceId
            : undefined,
          privacyDomainId: body.data.privacyDomainId,
          code: /^PC-[A-Z0-9-]+$/u.test(code) ? code : 'PC-IDENTITY-1002',
          disposition: 'DENIED',
        })}\n`,
      );
      return reply.code(code === 'PC-AUTH-0003' ? 401 : 403).send({ code });
    }
  });

  app.post('/internal/v1/local/configuration/authorize', async (request, reply) => {
    if (!authorized(request.headers.authorization, config.internalToken)) {
      return reply.code(403).send({ code: 'PC-AUTH-0005' });
    }
    const body = z
      .strictObject({
        sessionToken: z.string().min(1),
        idempotencyKey: z.string().min(1).max(256).optional(),
        privacyDomainId: z.uuid(),
        actionIntentId: z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u),
        catalogOperationId: z
          .string()
          .regex(/^[A-Z][A-Z0-9-]+$/u)
          .optional(),
        actionIntentDigest: z
          .string()
          .regex(/^sha256:[0-9a-f]{64}$/u)
          .optional(),
        resourceId: z.uuid(),
        candidateDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
        expectedRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
        csrfToken: z.string().min(32).max(256),
        origin: z.url(),
        host: z.string().min(1).max(255),
      })
      .safeParse(request.body);
    if (!body.success) return reply.code(422).send({ code: 'PC-IDENTITY-1004' });
    try {
      await kernel.verifyCsrf(
        body.data.sessionToken,
        body.data.actionIntentId,
        body.data.origin,
        body.data.host,
        body.data.csrfToken,
      );
      const proof = await authorizeLocalConfigurationMutation(
        pool,
        kernel,
        body.data,
        identityRuntimeCrypto,
      );
      return {
        ...proof,
        ...(proof.evidenceKind === 'IDENTITY_RUNTIME' ||
        proof.evidenceKind === 'IDENTITY_RUNTIME_STEP_UP'
          ? { signerKeyDigest: proof.signerKeyDigest.toString('base64') }
          : {}),
        evidenceCbor: proof.evidenceCbor.toString('base64'),
        evidenceDigest: proof.evidenceDigest.toString('base64'),
        coseSign1: proof.coseSign1.toString('base64'),
        ...(!('webauthnCoseSign1' in proof) || proof.webauthnAssertionBindingDigest === undefined
          ? {}
          : {
              webauthnAssertionBindingDigest:
                proof.webauthnAssertionBindingDigest.toString('base64'),
            }),
        ...(!('webauthnCoseSign1' in proof) || proof.webauthnSignerCredentialId === undefined
          ? {}
          : { webauthnSignerCredentialId: proof.webauthnSignerCredentialId }),
        ...(!('webauthnCoseSign1' in proof) || proof.webauthnEvidenceCbor === undefined
          ? {}
          : { webauthnEvidenceCbor: proof.webauthnEvidenceCbor.toString('base64') }),
        ...(!('webauthnCoseSign1' in proof) || proof.webauthnEvidenceDigest === undefined
          ? {}
          : { webauthnEvidenceDigest: proof.webauthnEvidenceDigest.toString('base64') }),
        ...(!('webauthnCoseSign1' in proof) || proof.webauthnCoseSign1 === undefined
          ? {}
          : { webauthnCoseSign1: proof.webauthnCoseSign1.toString('base64') }),
      };
    } catch (error) {
      const code =
        error instanceof Error && 'code' in error ? String(error.code) : 'PC-IDENTITY-1005';
      return reply.code(code === 'PC-AUTH-0003' ? 401 : 403).send({ code });
    }
  });

  return { app, kernel, pool, workloadMtlsCa, runtimeSnapshotPublisher };
}

async function main() {
  const config = await readLocalIdentityRuntimeConfig(process.env);
  if ((config.IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS ?? 60_000) > 60_000)
    process.stderr.write(
      `${JSON.stringify({ boundary: 'runtime_identity_snapshot', stage: 'local_qa_lifetime_enabled', lifetimeMs: config.IDENTITY_LOCAL_QA_RUNTIME_SNAPSHOT_TTL_MS })}\n`,
    );
  const { app, kernel, pool, workloadMtlsCa, runtimeSnapshotPublisher } =
    await buildLocalIdentityRuntime(config);
  const observer = await createQualificationObserverClient(
    config.IDENTITY_QUALIFICATION_OBSERVER_FILE,
  );
  app.decorate('qualificationObserverStatus', observer.status);
  let mtlsApp: ReturnType<typeof buildLocalWorkloadMtlsService> | undefined;
  let continuationApp: ReturnType<typeof buildSigningContinuationMtlsService> | undefined;
  let refreshPending: Promise<void> | undefined;
  let refreshTimer: ReturnType<typeof setInterval> | undefined;
  let closing: Promise<void> | undefined;
  let finishStartup!: () => void;
  const startupFinished = new Promise<void>((resolve) => {
    finishStartup = resolve;
  });
  const close = () => {
    closing ??= (async () => {
      // Stop accepting work, then drain real owners. A stuck database/request
      // cannot keep this actual service process alive indefinitely; durable
      // unknown originals remain recoverable after an unsuccessful drain.
      const deadline = setTimeout(() => {
        process.stderr.write('IDENTITY_RUNTIME|DRAIN_TIMEOUT\n');
        process.exit(1);
      }, 45000);
      deadline.unref();
      try {
        await startupFinished;
        clearInterval(refreshTimer);
        const results = await Promise.allSettled([
          observer.close(),
          refreshPending,
          app.close(),
          mtlsApp?.close(),
          continuationApp?.close(),
        ]);
        await pool.end();
        if (results.some((v) => v.status === 'rejected'))
          throw new Error('IDENTITY_DRAIN_UNAVAILABLE');
      } finally {
        clearTimeout(deadline);
      }
    })();
    return closing;
  };
  const stop = () => {
    void close().catch(() => {
      process.stderr.write('IDENTITY_RUNTIME|DRAIN_UNAVAILABLE\n');
      process.exitCode = 1;
    });
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
  try {
    mtlsApp = buildLocalWorkloadMtlsService(pool, kernel, {
      ca: workloadMtlsCa,
      certificate: await readFile(config.IDENTITY_MTLS_SERVER_CERT_FILE),
      privateKey: await readFile(config.IDENTITY_MTLS_SERVER_KEY_FILE),
    });
    if (closing) throw new Error('IDENTITY_DRAINING');
    const continuationCrypto = await readLocalSigningContinuationCrypto(config);
    if (closing) throw new Error('IDENTITY_DRAINING');
    if (continuationCrypto) {
      continuationApp = buildSigningContinuationMtlsService(
        pool,
        new SigningContinuationIssuer(pool, continuationCrypto.sign, continuationCrypto.verify),
        {
          ca: await readFile(config.IDENTITY_SIGNING_CONTINUATION_CLIENT_CA_FILE!),
          certificate: await readFile(config.IDENTITY_MTLS_SERVER_CERT_FILE),
          privateKey: await readFile(config.IDENTITY_MTLS_SERVER_KEY_FILE),
        },
      );
      const [host, port] = config.IDENTITY_SIGNING_CONTINUATION_LISTEN!.split(':');
      if (closing) throw new Error('IDENTITY_DRAINING');
      await continuationApp.listen({ host, port: Number(port) });
    }
    const [host, portText] = config.IDENTITY_LISTEN.split(':');
    const [mtlsHost, mtlsPortText] = config.IDENTITY_MTLS_LISTEN.split(':');
    if (closing) throw new Error('IDENTITY_DRAINING');
    await mtlsApp.listen({ host: mtlsHost, port: Number(mtlsPortText) });
    if (closing) throw new Error('IDENTITY_DRAINING');
    await app.listen({ host, port: Number(portText) });
    if (closing) throw new Error('IDENTITY_DRAINING');
    const refresh = () => {
      if (refreshPending !== undefined || closing) return;
      refreshPending = runtimeSnapshotPublisher
        .refreshPublishedTargets(
          pool,
          config.IDENTITY_LOCAL_PARTICIPANT_ID,
          config.IDENTITY_LOCAL_PRIVACY_DOMAIN_ID,
        )
        .then((result) => {
          if (result.failed > 0)
            app.log.warn(
              { code: 'IDENTITY_RUNTIME_SNAPSHOT_REFRESH_INCOMPLETE' },
              'Runtime snapshot refresh incomplete',
            );
        })
        .catch(() => {
          app.log.warn(
            { code: 'IDENTITY_RUNTIME_SNAPSHOT_REFRESH_UNAVAILABLE' },
            'Runtime snapshot refresh unavailable',
          );
        })
        .finally(() => {
          refreshPending = undefined;
        });
    };
    refreshTimer = setInterval(refresh, 5000);
    refresh();
    void observer.start().then((state) => {
      process.stdout.write(`IDENTITY_QUALIFICATION_OBSERVER|${state}|HISTORICAL_ONLY\n`);
    });
    finishStartup();
  } catch (first) {
    finishStartup();
    await close().catch(() => {
      process.stderr.write('IDENTITY_RUNTIME|STARTUP_CLEANUP_UNAVAILABLE\n');
    });
    throw first;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void main().catch((error: unknown) => {
    const errorCode =
      error instanceof Error &&
      'code' in error &&
      typeof error.code === 'string' &&
      /^[A-Z0-9_]{1,32}$/u.test(error.code)
        ? error.code
        : 'STARTUP_FAILURE';
    process.stderr.write(
      `${JSON.stringify({
        level: 'error',
        event: 'identity_runtime_stopped',
        errorName: error instanceof Error ? error.name : 'UnknownError',
        errorCode,
      })}\n`,
    );
    process.exitCode = 1;
  });
}
