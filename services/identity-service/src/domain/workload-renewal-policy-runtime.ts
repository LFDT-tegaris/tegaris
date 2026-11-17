import { readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import type { Pool } from 'pg';
import { z } from 'zod';
import { createLocalConfigurationAuthorizer } from '../../../control-api/src/configuration/local-authorizer.js';
import type { WorkloadRenewalPolicyApiOptions } from '../workload-renewal-policy-app.js';
import { createHttpBusinessSigningProvider } from './http-business-signing-provider.js';
import { createProviderBusinessReceiptSigner } from './provider-business-receipt-signer.js';

const file = z.string().min(1).refine(isAbsolute);
/** References only. Current DB qualification and exact grants are still checked
 * by the governed writer; configuration cannot grant issuer/376 authority. */
export const workloadRenewalPolicyRuntimeSchema = z.strictObject({
  version: z.literal(1),
  environmentId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u),
  providerOrigin: z.url().refine((value) => {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      url.pathname === '/' &&
      !url.search &&
      !url.hash
    );
  }),
  trustCaFile: file,
  clientCertificateFile: file,
  clientPrivateKeyFile: file,
  workloadCredentialId: z.uuidv7(),
});
export async function loadWorkloadRenewalPolicyRuntime(
  path: string | undefined,
  context: {
    readonly pool: Pool;
    readonly identityOrigin: string;
    readonly internalToken: string;
    readonly defaultPrivacyDomainId: string;
  },
): Promise<{ readonly api: WorkloadRenewalPolicyApiOptions; close(): void } | undefined> {
  if (path === undefined) return undefined;
  file.parse(path);
  const bytes = await readFile(path);
  if (bytes.length > 8192) throw new Error('Invalid renewal policy runtime configuration');
  const config = workloadRenewalPolicyRuntimeSchema.parse(JSON.parse(bytes.toString('utf8')));
  const [trustCa, certificate, privateKey] = await Promise.all([
    readFile(config.trustCaFile),
    readFile(config.clientCertificateFile),
    readFile(config.clientPrivateKeyFile),
  ]);
  const provider = createHttpBusinessSigningProvider({
    origin: config.providerOrigin,
    trustCa,
    certificate,
    privateKey,
  });
  return {
    api: {
      pool: context.pool,
      authorizer: createLocalConfigurationAuthorizer(
        context.identityOrigin,
        context.internalToken,
        context.defaultPrivacyDomainId,
      ),
      businessEvidence: {
        environmentId: config.environmentId,
        signer: createProviderBusinessReceiptSigner(provider, config.workloadCredentialId),
      },
    },
    close: () => provider.close(),
  };
}
