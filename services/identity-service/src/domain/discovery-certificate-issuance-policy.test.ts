import { expect, it } from 'vitest';
import { configuredDiscoveryCertificateIssuancePolicy } from './discovery-certificate-issuance-policy.js';
it('derives issuer operational deadlines and retry ceilings from environment configuration', () => {
  expect(configuredDiscoveryCertificateIssuancePolicy({})).toEqual({
    attemptMs: 120000,
    maximumAttempts: 3,
  });
  expect(
    configuredDiscoveryCertificateIssuancePolicy({
      IDENTITY_DISCOVERY_ISSUANCE_ATTEMPT_TTL_MS: '300000',
      IDENTITY_DISCOVERY_ISSUANCE_MAX_ATTEMPTS: '5',
    }),
  ).toEqual({ attemptMs: 300000, maximumAttempts: 5 });
  for (const value of ['0', '-1', '300001', 'NaN', '1.5', '001'])
    expect(() =>
      configuredDiscoveryCertificateIssuancePolicy({
        IDENTITY_DISCOVERY_ISSUANCE_ATTEMPT_TTL_MS: value,
      }),
    ).toThrow();
  expect(() =>
    configuredDiscoveryCertificateIssuancePolicy({
      IDENTITY_DISCOVERY_ISSUANCE_MAX_ATTEMPTS: '11',
    }),
  ).toThrow();
});
