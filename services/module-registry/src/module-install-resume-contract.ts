/** Only the existing minimum install command may use ordinary approval renewal. */
export const moduleInstallResumeBinding = Object.freeze({
  catalogOperationId: 'MOD-OP-INSTALL',
  actionIntentId: 'ACT-MODULE_CREATE_INSTALL-V1',
  resourceType: 'module',
  operationClass: 'CREATE',
} as const);

export function isModuleInstallResumeCandidate(candidate: {
  catalogOperationId: string;
  actionIntentId: string;
  resourceType: string;
  operationClass: string;
}): boolean {
  return Object.entries(moduleInstallResumeBinding).every(
    ([key, value]) => candidate[key as keyof typeof moduleInstallResumeBinding] === value,
  );
}

// Values are fixed owner constants; no request or database value becomes SQL.
export const moduleInstallResumeSqlTuple = `(${Object.values(moduleInstallResumeBinding)
  .map((value) => `'${value}'`)
  .join(',')})`;
