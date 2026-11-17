import { z } from 'zod';

/** Operational issuer deadlines are configuration, bounded by custody/approval
 * expiry at admission. These values never extend a signed authority lifetime. */
export const discoveryCertificateIssuancePolicy = z.strictObject({
  attemptMs: z.number().int().positive().max(300000),
  maximumAttempts: z.number().int().min(1).max(10),
});
export type DiscoveryCertificateIssuancePolicy = z.infer<typeof discoveryCertificateIssuancePolicy>;
export const defaultDiscoveryCertificateIssuancePolicy: DiscoveryCertificateIssuancePolicy = {
  attemptMs: 120000,
  maximumAttempts: 3,
};
export function configuredDiscoveryCertificateIssuancePolicy(
  environment: Readonly<Record<string, string | undefined>>,
) {
  const configured = (key: string, fallback: number) => {
    const value = environment[key];
    if (value === undefined) return fallback;
    if (!/^[1-9][0-9]*$/u.test(value))
      throw new Error('Invalid discovery issuer operational policy');
    return Number(value);
  };
  return discoveryCertificateIssuancePolicy.parse({
    attemptMs: configured(
      'IDENTITY_DISCOVERY_ISSUANCE_ATTEMPT_TTL_MS',
      defaultDiscoveryCertificateIssuancePolicy.attemptMs,
    ),
    maximumAttempts: configured(
      'IDENTITY_DISCOVERY_ISSUANCE_MAX_ATTEMPTS',
      defaultDiscoveryCertificateIssuancePolicy.maximumAttempts,
    ),
  });
}
