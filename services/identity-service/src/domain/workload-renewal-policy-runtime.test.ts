import { expect, it } from 'vitest';
import {
  workloadRenewalPolicyRuntimeSchema,
  loadWorkloadRenewalPolicyRuntime,
} from './workload-renewal-policy-runtime.js';
const config = {
  version: 1,
  environmentId: 'local-governed-policy',
  providerOrigin: 'https://signing-provider:8443/',
  trustCaFile: '/run/secrets/signing-ca.pem',
  clientCertificateFile: '/run/secrets/client-cert.pem',
  clientPrivateKeyFile: '/run/secrets/client-key.pem',
  workloadCredentialId: '018f0000-0000-7000-8000-000000000001',
};
it('accepts exact qualified transport references without inline keys, scope or routine authority', () => {
  expect(workloadRenewalPolicyRuntimeSchema.parse(config)).toEqual(config);
  for (const fields of [
    { privateKey: 'inline' },
    { participantId: 'caller-scope' },
    { purpose: 376 },
    { approved: true },
    { policyDigest: 'caller-policy' },
  ])
    expect(workloadRenewalPolicyRuntimeSchema.safeParse({ ...config, ...fields }).success).toBe(
      false,
    );
});
it.each([
  'http://signing-provider/',
  'https://user:password@signing-provider/',
  'https://signing-provider/path',
  'https://signing-provider/?purpose=376',
  'https://signing-provider/#purpose',
])('denies unqualified origin %s', (providerOrigin) => {
  expect(workloadRenewalPolicyRuntimeSchema.safeParse({ ...config, providerOrigin }).success).toBe(
    false,
  );
});
it('requires absolute custody references and preserves an absent installation without opening files or connections', async () => {
  expect(
    workloadRenewalPolicyRuntimeSchema.safeParse({
      ...config,
      clientPrivateKeyFile: 'relative/key.pem',
    }).success,
  ).toBe(false);
  await expect(loadWorkloadRenewalPolicyRuntime(undefined, {} as never)).resolves.toBeUndefined();
});
