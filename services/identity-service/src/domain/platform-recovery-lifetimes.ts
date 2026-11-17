import { z } from 'zod';
import {
  localQaDurationMultiplier,
  type LocalQaDurationEnvironment,
} from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';

/** Defaults and security ceilings live here; environment values govern newly issued records only. */
export const recoveryLifetimeLimits = {
  rootEnrollmentMs: 60 * 60 * 1000,
  qa10RootEnrollmentMs: 10 * 60 * 60 * 1000,
  leaseMs: 15 * 60 * 1000,
  administratorMs: 60 * 60 * 1000,
  qaLeaseMs: 60 * 60 * 1000,
  qaAdministratorMs: 24 * 60 * 60 * 1000,
  qa10LeaseMs: 10 * 15 * 60 * 1000,
  // Historical signed QA intents used this ceiling. Parsing them must not rewrite history.
  legacyQa10LeaseMs: 48 * 60 * 60 * 1000,
  qa10AdministratorMs: 10 * 60 * 60 * 1000,
} as const;
export const recoveryLifetimeSettings = z
  .strictObject({
    profile: z.enum(['C17', 'LOCAL_QA', 'LOCAL_QA_10X']),
    leaseMs: z.number().int().positive().max(recoveryLifetimeLimits.legacyQa10LeaseMs),
    administratorMs: z.number().int().positive().max(recoveryLifetimeLimits.qaAdministratorMs),
  })
  .superRefine((value, ctx) => {
    if (value.profile === 'LOCAL_QA' && value.leaseMs > recoveryLifetimeLimits.qaLeaseMs)
      ctx.addIssue({ code: 'custom', message: 'Recovery lifetime exceeds legacy QA limits' });
    if (
      value.profile === 'LOCAL_QA_10X' &&
      value.administratorMs > recoveryLifetimeLimits.qa10AdministratorMs
    )
      ctx.addIssue({ code: 'custom', message: 'Recovery lifetime exceeds temporary QA limits' });
    if (
      value.profile === 'C17' &&
      (value.leaseMs > recoveryLifetimeLimits.leaseMs ||
        value.administratorMs > recoveryLifetimeLimits.administratorMs)
    )
      ctx.addIssue({ code: 'custom', message: 'Recovery lifetime exceeds normal limits' });
  });
export type RecoveryLifetimeSettings = z.infer<typeof recoveryLifetimeSettings>;
export const defaultRecoveryLifetimes: RecoveryLifetimeSettings = {
  profile: 'C17',
  leaseMs: recoveryLifetimeLimits.leaseMs,
  administratorMs: recoveryLifetimeLimits.administratorMs,
};

export function readRecoveryLifetimes(
  environment: LocalQaDurationEnvironment & {
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE?: string;
    IDENTITY_RECOVERY_LEASE_TTL_MS?: number;
    IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS?: number;
  },
): RecoveryLifetimeSettings {
  const temporaryQa = localQaDurationMultiplier(environment) === 10;
  const leaseMs =
    environment.IDENTITY_RECOVERY_LEASE_TTL_MS ??
    (temporaryQa ? recoveryLifetimeLimits.qa10LeaseMs : defaultRecoveryLifetimes.leaseMs);
  const administratorMs =
    environment.IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS ??
    (temporaryQa
      ? recoveryLifetimeLimits.qa10AdministratorMs
      : defaultRecoveryLifetimes.administratorMs);
  if (temporaryQa && leaseMs > recoveryLifetimeLimits.qa10LeaseMs)
    throw new Error('New QA recovery lifetime exceeds tenfold normal limit');
  const profile = temporaryQa
    ? 'LOCAL_QA_10X'
    : leaseMs > recoveryLifetimeLimits.leaseMs ||
        administratorMs > recoveryLifetimeLimits.administratorMs
      ? 'LOCAL_QA'
      : 'C17';
  if (profile === 'LOCAL_QA' && environment.OPENPC_LOCAL_RUNTIME_QA_FIXTURE !== '1')
    throw new Error('Recovery lifetime requires local QA fixture');
  return recoveryLifetimeSettings.parse({ profile, leaseMs, administratorMs });
}
