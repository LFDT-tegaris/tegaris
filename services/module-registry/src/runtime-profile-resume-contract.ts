/** Continuation retains the original immutable target/profile binding intent. */
export const runtimeProfileResumeBinding = Object.freeze({
  catalogOperationId: 'CFG-OP-CREATE-RUNTIME-TARGET-PROFILE',
  actionIntentId: 'ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1',
  resourceType: 'runtime-target-profile-binding',
  operationClass: 'CREATE',
} as const);

export function isRuntimeProfileResumeCandidate(candidate: {
  catalogOperationId: string;
  actionIntentId: string;
  resourceType: string;
  operationClass: string;
}): boolean {
  return Object.entries(runtimeProfileResumeBinding).every(
    ([key, value]) => candidate[key as keyof typeof runtimeProfileResumeBinding] === value,
  );
}

// Fixed owner constants only; no caller value is interpolated into SQL.
export const runtimeProfileResumeSqlTuple = `(${Object.values(runtimeProfileResumeBinding)
  .map((value) => `'${value}'`)
  .join(',')})`;
