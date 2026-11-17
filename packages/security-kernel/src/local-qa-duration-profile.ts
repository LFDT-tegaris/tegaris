/** Temporary, explicit local QA execution profile. Normal security freshness
 * and every existing signed expiry remain independent of execution budgets. */
export const localQaDurationProfileName = 'LOCAL_QA_10X' as const;
export interface LocalQaDurationEnvironment {
  readonly OPENPC_LOCAL_RUNTIME?: string;
  readonly OPENPC_LOCAL_RUNTIME_QA_FIXTURE?: string;
  readonly OPENPC_LOCAL_QA_DURATION_PROFILE?: string;
  readonly OPENPC_LOCAL_QA_EXECUTION_PROFILE?: string;
}
export function localQaDurationMultiplier(
  environment: LocalQaDurationEnvironment | NodeJS.ProcessEnv,
): 1 | 10 {
  const profile = environment.OPENPC_LOCAL_QA_DURATION_PROFILE;
  if (profile === undefined) return 1;
  if (
    profile !== localQaDurationProfileName ||
    environment.OPENPC_LOCAL_RUNTIME !== '1' ||
    environment.OPENPC_LOCAL_RUNTIME_QA_FIXTURE !== '1'
  )
    throw new Error('Duration profile requires explicit local QA runtime');
  return 10;
}
export function localQaExecutionTimeoutMs(
  normalMs: number,
  environment: LocalQaDurationEnvironment | NodeJS.ProcessEnv = process.env,
): number {
  if (!Number.isSafeInteger(normalMs) || normalMs < 1 || normalMs > 3_600_000)
    throw new Error('Invalid finite execution timeout');
  const durationMultiplier = localQaDurationMultiplier(environment);
  const executionProfile = environment.OPENPC_LOCAL_QA_EXECUTION_PROFILE;
  const multiplier =
    executionProfile === undefined
      ? durationMultiplier
      : localQaDurationMultiplier({
          ...environment,
          OPENPC_LOCAL_QA_DURATION_PROFILE: executionProfile,
        });
  return normalMs * multiplier;
}
