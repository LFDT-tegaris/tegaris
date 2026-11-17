import { readFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import {
  buildLocalIdentityRuntime,
  readLocalIdentityRuntimeConfig,
} from '../../../services/identity-service/src/local-runtime.js';
import { governedInitialEnrollmentProfileSchema } from '../../../services/identity-service/src/domain/governed-initial-enrollment.js';
import { closeFixtureResources } from './close-fixture-resources.js';

/** Resume the exact isolated Identity signer/configuration. This writes no
 * material, creates no initial trust, and never copies a retained database. */
export async function retainedGovernedEnrollmentRuntime(directory: string, databaseUrl: string) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent || !directory.startsWith(`${parent}/`) || (await realpath(directory)) !== directory)
    throw new Error('Exact retained fixture directory required');
  const file = (name: string) => join(directory, name);
  const profile = governedInitialEnrollmentProfileSchema.parse(
    JSON.parse(await readFile(file('initial-enrollment.json'), 'utf8')),
  );
  const account = profile.accounts[0]!;
  const database = new URL(databaseUrl);
  if ((await readFile(file('database'), 'utf8')) !== decodeURIComponent(database.password))
    throw new Error('Retained database binding differs');
  const config = await readLocalIdentityRuntimeConfig({
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
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
    IDENTITY_LOCAL_OPERATOR_PRINCIPAL_ID: '018f0000-0000-7000-8000-000000000111',
    IDENTITY_LOCAL_VIEWER_PRINCIPAL_ID: '018f0000-0000-7000-8000-000000000112',
    IDENTITY_LOCAL_PARTICIPANT_ID: account.participantId,
    IDENTITY_LOCAL_PRIVACY_DOMAIN_ID: account.privacyDomainId,
    IDENTITY_OIDC_ISSUER: account.issuer,
    IDENTITY_OIDC_CLIENT_ID: account.audience,
    IDENTITY_OIDC_REDIRECT_URI: `${profile.origin}/callback`,
    IDENTITY_RECOVERY_ATTESTATION_PROFILE_FILE: file('hardware-attestation.json'),
    IDENTITY_GOVERNED_INITIAL_ENROLLMENT_PROFILE_FILE: file('initial-enrollment.json'),
    IDENTITY_MTLS_CA_FILE: file('tls.crt'),
    IDENTITY_MTLS_SERVER_CERT_FILE: file('tls.crt'),
    IDENTITY_MTLS_SERVER_KEY_FILE: file('tls.key'),
    IDENTITY_WORKLOAD_ISSUER_URL: 'http://127.0.0.1:1',
    IDENTITY_WORKLOAD_ISSUER_TOKEN_FILE: file('internal'),
    IDENTITY_MTLS_LISTEN: '127.0.0.1:1',
    IDENTITY_LISTEN: '127.0.0.1:1',
  });
  let identity: Awaited<ReturnType<typeof buildLocalIdentityRuntime>> | undefined;
  const close = async () => {
    const old = identity;
    identity = undefined;
    await closeFixtureResources([
      async () => {
        await old?.app.close();
      },
      async () => {
        await old?.pool.end();
      },
    ]);
  };
  try {
    identity = await buildLocalIdentityRuntime(config);
    const identityUrl = await identity.app.listen({ host: '127.0.0.1', port: 0 });
    return {
      directory,
      profile,
      identityUrl,
      identityInternalToken: await readFile(file('internal'), 'utf8'),
      async restartIdentity() {
        await close();
        identity = await buildLocalIdentityRuntime(config);
        await identity.app.listen({ host: '127.0.0.1', port: Number(new URL(identityUrl).port) });
      },
      close,
    };
  } catch (error) {
    await closeFixtureResources([close], { error });
    throw error;
  }
}
