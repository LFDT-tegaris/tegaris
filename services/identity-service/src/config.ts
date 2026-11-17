import { z } from 'zod';

export const identityServiceConfigSchema = z.strictObject({
  databaseSecretRef: z.string().regex(/^secret:\/\/[a-z0-9-]+\/[A-Za-z0-9_.-]+#[A-Za-z0-9_.-]+$/u),
  oidcIssuer: z.url(),
  oidcClientId: z.string().min(1),
  oidcClientSecretRef: z
    .string()
    .regex(/^secret:\/\/[a-z0-9-]+\/[A-Za-z0-9_.-]+#[A-Za-z0-9_.-]+$/u),
  oidcRedirectUri: z.url(),
  sessionIdleTimeout: z.literal('PT30M'),
  sessionAbsoluteTimeout: z.literal('PT12H'),
  stepUpValidity: z.literal('PT5M'),
  workloadTlsMinimum: z.literal('TLS1.3'),
  workloadCertificateMaximumLifetime: z.literal('PT24H'),
  workloadCertificateRotation: z.literal('PT12H'),
  recoveryLease: z.literal('PT15M'),
});

export type IdentityServiceConfig = z.infer<typeof identityServiceConfigSchema>;
