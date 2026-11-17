import { moduleMutationOperation } from '@openpc/security-kernel';
import { describe, expect, it } from 'vitest';
import { isModuleInstallResumeCandidate } from './module-install-resume-contract.js';

describe('minimum module install approval resume', () => {
  it('recognizes the canonical governed install command', () => {
    const operation = moduleMutationOperation('MOD-OP-INSTALL')!;
    expect(operation.makerCheckerRequired).toBe(true);
    expect(operation.stepUpRequired).toBe(true);
    expect(isModuleInstallResumeCandidate(operation)).toBe(true);
  });

  it.each(['MOD-OP-REGISTER', 'MOD-OP-ENABLE', 'MOD-OP-DISABLE'])(
    'does not extend renewal to %s',
    (operation) => {
      expect(isModuleInstallResumeCandidate(moduleMutationOperation(operation)!)).toBe(false);
    },
  );

  it.each([
    { actionIntentId: 'ACT-MODULES_CREATE_RESOURCE-V1' },
    { resourceType: 'modules' },
    { operationClass: 'ACTIVATE' },
    { catalogOperationId: 'MOD-OP-ENABLE' },
  ])('rejects a mismatched canonical binding %j', (changed) => {
    expect(
      isModuleInstallResumeCandidate({ ...moduleMutationOperation('MOD-OP-INSTALL')!, ...changed }),
    ).toBe(false);
  });
});
