import { loadModuleReleaseCatalog } from './module-release-catalog.js';
import { createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createLocalIdentityRuntimeVerifier } from '../../identity-service/src/domain/identity-runtime-crypto.js';

import { Pool } from 'pg';
import { z } from 'zod';

import { buildPolicyService, HttpPolicyIdentityGateway } from './policy-http.js';
import { createPolicyArtifactCompilerSigner } from './domain/policy-artifact-compiler.js';

const schema = z.object({
  OPENPC_LOCAL_RUNTIME: z.literal('1'),
  OPENPC_LOCAL_RUNTIME_QA_FIXTURE: z.enum(['0', '1']).default('0'),
  POLICY_MODULE_RELEASE_CATALOG_FILE: z.string().min(1).optional(),
  POLICY_MODULE_RELEASE_TRUST_FILE: z.string().min(1).optional(),
  POLICY_DATABASE_HOST: z.string().min(1),
  POLICY_DATABASE_PORT: z.coerce.number().int().min(1).max(65_535),
  POLICY_DATABASE_NAME: z.string().regex(/^[a-z][a-z0-9_]*$/u),
  POLICY_DATABASE_USER: z.string().regex(/^[a-z][a-z0-9_]*$/u),
  POLICY_DATABASE_PASSWORD_FILE: z.string().min(1),
  POLICY_INTERNAL_TOKEN_FILE: z.string().min(1),
  POLICY_IDENTITY_INTERNAL_TOKEN_FILE: z.string().min(1),
  POLICY_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES: z.string().min(1).optional(),
  POLICY_ARTIFACT_SIGNER_PUBLIC_KEY_FILE: z.string().min(1),
  POLICY_ARTIFACT_SIGNER_PRIVATE_KEY_FILE: z.string().min(1).optional(),
  POLICY_IDENTITY_URL: z.url(),
  POLICY_LISTEN: z.string().regex(/^[^:]+:[1-9][0-9]{0,4}$/u),
});

async function secret(path: string): Promise<string> {
  const value = (await readFile(path, 'utf8')).trim();
  if (value.length < 32 || value.length > 256 || !/^\S+$/u.test(value)) {
    throw new Error('invalid local policy secret');
  }
  return value;
}

export async function buildLocalPolicyRuntime(environment: NodeJS.ProcessEnv) {
  const config = schema.parse(environment);
  const [password, internalToken, identityToken, signerPem] = await Promise.all([
    secret(config.POLICY_DATABASE_PASSWORD_FILE),
    secret(config.POLICY_INTERNAL_TOKEN_FILE),
    secret(config.POLICY_IDENTITY_INTERNAL_TOKEN_FILE),
    readFile(config.POLICY_ARTIFACT_SIGNER_PUBLIC_KEY_FILE, 'utf8'),
  ]);
  const signer = createPublicKey(signerPem).export({ format: 'der', type: 'spki' });
  const compilerSigner = config.POLICY_ARTIFACT_SIGNER_PRIVATE_KEY_FILE
    ? createPolicyArtifactCompilerSigner(
        await readFile(config.POLICY_ARTIFACT_SIGNER_PRIVATE_KEY_FILE, 'utf8'),
      )
    : undefined;
  if (compilerSigner && !compilerSigner.publicKeySpkiDer.equals(signer))
    throw new Error('Policy compiler signing trust mismatch');
  const pool = new Pool({
    host: config.POLICY_DATABASE_HOST,
    port: config.POLICY_DATABASE_PORT,
    database: config.POLICY_DATABASE_NAME,
    user: config.POLICY_DATABASE_USER,
    password,
    max: 8,
    options: `-c openpc.local_qa_runtime=${config.OPENPC_LOCAL_RUNTIME_QA_FIXTURE}`,
  });
  const moduleFiles = [
    config.POLICY_MODULE_RELEASE_CATALOG_FILE,
    config.POLICY_MODULE_RELEASE_TRUST_FILE,
  ];
  if (
    moduleFiles.some((value) => value !== undefined) &&
    moduleFiles.some((value) => value === undefined)
  ) {
    throw new Error('module release catalog requires explicit trust and privacy configuration');
  }
  const moduleReleaseCatalog =
    config.POLICY_MODULE_RELEASE_CATALOG_FILE === undefined
      ? undefined
      : await loadModuleReleaseCatalog(
          config.POLICY_MODULE_RELEASE_CATALOG_FILE,
          config.POLICY_MODULE_RELEASE_TRUST_FILE!,
        );
  const app = buildPolicyService({
    identityRuntimeVerifier: config.POLICY_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES
      ? createLocalIdentityRuntimeVerifier(
          await Promise.all(
            config.POLICY_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES.split(',').map((path) =>
              readFile(path),
            ),
          ),
        )
      : undefined,
    moduleReleaseCatalog,
    pool,
    identityGateway: new HttpPolicyIdentityGateway(config.POLICY_IDENTITY_URL, identityToken),
    trustedArtifactSigners: [{ publicKeySpkiDer: signer }],
    ...(compilerSigner ? { artifactCompilerSigner: compilerSigner } : {}),
    internalToken,
  });
  return { app, pool, listen: config.POLICY_LISTEN };
}

async function main() {
  const { app, pool, listen } = await buildLocalPolicyRuntime(process.env);
  const [host, port] = listen.split(':');
  await app.listen({ host, port: Number(port) });
  const close = async () => {
    await app.close();
    await pool.end();
  };
  process.once('SIGTERM', () => void close());
  process.once('SIGINT', () => void close());
}

if (import.meta.url === `file://${process.argv[1]}`) {
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
      `${JSON.stringify({ level: 'error', event: 'policy_runtime_stopped', boundary: 'startup', code, configurationFields })}\n`,
    );
    process.exitCode = 1;
  });
}
