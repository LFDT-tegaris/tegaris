import { describe, expect, it } from 'vitest';

import {
  identityContractTypes,
  identityErrors,
  identityEvents,
  identityOperations,
  identityStates,
} from './catalog.js';

describe('identity contract catalog', () => {
  it('owns the frozen identity-side denominator', () => {
    expect(identityContractTypes).toHaveLength(9);
    expect(identityOperations).toHaveLength(15);
    expect(Object.values(identityStates).flat()).toHaveLength(32);
    expect(identityErrors).toHaveLength(16);
    expect(identityEvents).toHaveLength(5);
  });

  it('makes every operation fail closed', () => {
    for (const operation of identityOperations) {
      expect(operation.authorization).toBe('EFFECTIVE_INTERSECTION_ONLY');
      expect(operation.denial).toBe('TERMINAL_NON_LEAKING');
      expect(operation.idempotency).toBe('EXACT_OPERATION_ID_AND_DIGEST');
    }
  });
});
