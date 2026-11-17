import { localQaDurationMultiplier } from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';

/** Approval expiry range: PT5M through P30D. Applies only when an approval is created. */
export function policyApprovalTtlMs(env: Readonly<Record<string, string | undefined>>): number {
  const raw = env.POLICY_APPROVAL_TTL_MS ?? '1800000';
  const value = Number(raw);
  if (
    !/^[1-9][0-9]*$/u.test(raw) ||
    !Number.isSafeInteger(value) ||
    value < 300_000 ||
    value > 2_592_000_000
  )
    throw new Error('Invalid POLICY_APPROVAL_TTL_MS');
  // This setting is the normal baseline, including when explicitly configured.
  // Apply the selected profile once when issuing a new approval.
  const configured =
    value *
    localQaDurationMultiplier({
      OPENPC_LOCAL_RUNTIME: env.OPENPC_LOCAL_RUNTIME,
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: env.OPENPC_LOCAL_RUNTIME_QA_FIXTURE,
      OPENPC_LOCAL_QA_DURATION_PROFILE: env.OPENPC_LOCAL_QA_DURATION_PROFILE,
    });
  if (configured > 2_592_000_000) throw new Error('Invalid POLICY_APPROVAL_TTL_MS');
  return configured;
}
