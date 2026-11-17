import { expect, it } from 'vitest';
import {
  readRecoveryLifetimes,
  defaultRecoveryLifetimes,
  recoveryLifetimeSettings,
  recoveryLifetimeLimits,
} from './platform-recovery-lifetimes.js';
import { assertPlatformRecoveryIntent } from './platform-recovery-policy.js';
import {
  platformRecoveryFixture,
  rootExpiryPlatformRecoveryFixture,
  pendingPlatformRecoveryFixture,
  pendingExpiryPlatformRecoveryFixture,
} from './platform-recovery.test-fixture.js';
import { platformAdministrationRecoveryEnrollment } from '../contracts/platform-recovery.js';

it('retains normal defaults and accepts shorter environment-controlled durations', () => {
  expect(readRecoveryLifetimes({})).toEqual(defaultRecoveryLifetimes);
  expect(readRecoveryLifetimes({ IDENTITY_RECOVERY_LEASE_TTL_MS: 600000 })).toMatchObject({
    profile: 'C17',
    leaseMs: 600000,
  });
});
it.each([0, -1, 900000.5, NaN, Infinity, 3600001])(
  'rejects invalid custody setting %s',
  (leaseMs) => {
    expect(() =>
      readRecoveryLifetimes({
        OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
        IDENTITY_RECOVERY_LEASE_TTL_MS: leaseMs,
      }),
    ).toThrow();
  },
);
it('requires an explicit QA runtime for longer custody or administrator scopes', () => {
  for (const settings of [
    { IDENTITY_RECOVERY_LEASE_TTL_MS: 3600000 },
    { IDENTITY_RECOVERY_ADMINISTRATOR_TTL_MS: 28800000 },
  ]) {
    expect(() => readRecoveryLifetimes(settings)).toThrow('local QA');
    expect(
      readRecoveryLifetimes({ ...settings, OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1' }).profile,
    ).toBe('LOCAL_QA');
  }
});
it('admits longer signed custody in QA while preserving the original historical intent', () => {
  const { source, intent } = platformRecoveryFixture();
  const original = structuredClone(intent);
  const next = structuredClone(intent);
  next.lifetimes = { profile: 'LOCAL_QA', leaseMs: 3600000, administratorMs: 28800000 };
  next.validUntil = source.enrollment.validUntil;
  expect(Date.parse(next.validUntil) - Date.parse(next.validFrom)).toBeGreaterThan(900000);
  expect(() => assertPlatformRecoveryIntent(next, source)).not.toThrow();
  const normal = {
    ...next,
    lifetimes: {
      ...next.lifetimes,
      profile: 'C17' as const,
      leaseMs: 900000,
      administratorMs: 3600000,
    },
  };
  expect(() => assertPlatformRecoveryIntent(normal, source)).toThrow();
  expect(intent).toEqual(original);
});
it('denies an otherwise valid QA-profile intent outside local QA or with hardware enrollment', () => {
  const { source, intent } = platformRecoveryFixture();
  intent.lifetimes = { profile: 'LOCAL_QA', leaseMs: 3600000, administratorMs: 28800000 };
  expect(() => assertPlatformRecoveryIntent(intent, source)).not.toThrow();
  source.localQaEnabled = false;
  expect(() => assertPlatformRecoveryIntent(intent, source)).toThrow();
  source.localQaEnabled = true;
  source.enrollment.assurance = 'HARDWARE_ATTESTED';
  expect(() => assertPlatformRecoveryIntent(intent, source)).toThrow();
});

it('requires all temporary opt-ins for a new tenfold fifteen-minute signed recovery profile', () => {
  const environment = {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
  };
  expect(readRecoveryLifetimes(environment)).toEqual({
    profile: 'LOCAL_QA_10X',
    leaseMs: 9_000_000,
    administratorMs: 36_000_000,
  });
  expect(() =>
    readRecoveryLifetimes({ ...environment, OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '0' }),
  ).toThrow();
  expect(() =>
    readRecoveryLifetimes({ ...environment, IDENTITY_RECOVERY_LEASE_TTL_MS: 9_000_001 }),
  ).toThrow();
  expect(() =>
    readRecoveryLifetimes({
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
      IDENTITY_RECOVERY_LEASE_TTL_MS: 172_800_000,
    }),
  ).toThrow();
});

it('preserves historical signed 48-hour values but forbids issuing them again', () => {
  const historical = { profile: 'LOCAL_QA_10X', leaseMs: 172_800_000, administratorMs: 36_000_000 };
  expect(recoveryLifetimeSettings.parse(historical)).toEqual(historical);
  const qa = {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
  };
  expect(() =>
    readRecoveryLifetimes({ ...qa, IDENTITY_RECOVERY_LEASE_TTL_MS: historical.leaseMs }),
  ).toThrow();
  expect(readRecoveryLifetimes({ ...qa, IDENTITY_RECOVERY_LEASE_TTL_MS: 600_000 }).leaseMs).toBe(
    600_000,
  );
});

it('keeps the new tenfold lease inside the original enrollment and Root ceilings', () => {
  const { source, intent } = platformRecoveryFixture();
  const original = structuredClone(intent);
  const next = structuredClone(intent);
  next.lifetimes = readRecoveryLifetimes({
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
  });
  next.validUntil = source.enrollment.validUntil;
  expect(Date.parse(next.validUntil) - Date.parse(next.validFrom)).toBeLessThan(
    next.lifetimes.leaseMs,
  );
  expect(() => assertPlatformRecoveryIntent(next, source)).not.toThrow();
  expect(() =>
    assertPlatformRecoveryIntent(
      { ...next, validUntil: new Date(Date.parse(next.validUntil) + 1).toISOString() },
      source,
    ),
  ).toThrow();
  source.root.grantable.validUntilNs = (
    BigInt(Date.parse(next.validUntil) - 1) * 1_000_000n
  ).toString();
  expect(() => assertPlatformRecoveryIntent(next, source)).toThrow();
  expect(intent).toEqual(original);
});

it.each([
  ['Root expiry', rootExpiryPlatformRecoveryFixture],
  ['pending continuation', pendingPlatformRecoveryFixture],
  ['pending administrator expiry', pendingExpiryPlatformRecoveryFixture],
] as const)(
  'admits a fresh ten-hour QA %s enrollment without rewriting the original',
  (_name, fixture) => {
    const original = fixture().source.enrollment;
    const before = JSON.stringify(original);
    const next = {
      ...structuredClone(original),
      validUntil: new Date(
        Date.parse(original.validFrom) + recoveryLifetimeLimits.qa10RootEnrollmentMs,
      ).toISOString(),
    };
    expect(platformAdministrationRecoveryEnrollment.parse(next)).toEqual(next);
    expect(
      platformAdministrationRecoveryEnrollment.safeParse({
        ...next,
        validUntil: new Date(Date.parse(next.validUntil) + 1).toISOString(),
      }).success,
    ).toBe(false);
    expect(JSON.stringify(original)).toBe(before);
  },
);

it.each([
  rootExpiryPlatformRecoveryFixture,
  pendingPlatformRecoveryFixture,
  pendingExpiryPlatformRecoveryFixture,
])('retains the one-hour hardware enrollment ceiling', (fixture) => {
  const original = fixture().source.enrollment;
  const normal = {
    ...structuredClone(original),
    assurance: 'HARDWARE_ATTESTED' as const,
    validUntil: new Date(
      Date.parse(original.validFrom) + recoveryLifetimeLimits.rootEnrollmentMs,
    ).toISOString(),
  };
  expect(platformAdministrationRecoveryEnrollment.safeParse(normal).success).toBe(true);
  expect(
    platformAdministrationRecoveryEnrollment.safeParse({
      ...normal,
      validUntil: new Date(Date.parse(normal.validUntil) + 1).toISOString(),
    }).success,
  ).toBe(false);
});
