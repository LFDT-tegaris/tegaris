import { configurationMutationOperation } from '@openpc/security-kernel';
import { describe, expect, it } from 'vitest';
import { isRuntimeProfileResumeCandidate } from './runtime-profile-resume-contract.js';

describe('runtime profile binding approval continuation', () => {
  const operation = configurationMutationOperation('CFG-OP-CREATE-RUNTIME-TARGET-PROFILE')!;

  it('retains the canonical action, independent approval and step-up requirements', () => {
    expect(operation).toBeDefined();
    expect(operation.makerCheckerRequired).toBe(true);
    expect(operation.stepUpRequired).toBe(true);
    expect(isRuntimeProfileResumeCandidate(operation)).toBe(true);
  });

  it.each([
    { catalogOperationId: 'CFG-OP-CREATE-RUNTIME-TARGET' },
    { actionIntentId: 'ACT-RUNTIME_TARGET_PROFILES_READ_RESOURCE-V1' },
    { resourceType: 'runtime-target' },
    { operationClass: 'UPDATE' },
  ])('rejects a different operation binding %j', (changed) => {
    expect(isRuntimeProfileResumeCandidate({ ...operation, ...changed })).toBe(false);
  });
});
