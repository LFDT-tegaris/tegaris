import { describe, expect, it } from 'vitest';

import { localOperationId } from './local-operation-id.js';

describe('local scoped operation identifiers', () => {
  it('emits distinct UUIDv7 values with the RFC variant required by database context', () => {
    const identifiers = Array.from({ length: 32 }, localOperationId);
    expect(new Set(identifiers)).toHaveLength(identifiers.length);
    for (const identifier of identifiers) {
      expect(identifier).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      );
    }
  });
});
