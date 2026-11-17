import { describe, expect, it } from 'vitest';

import { executionRegistry } from '../contracts/privacy-explorer-adapter.js';
import { createPrivacyExplorerExecutionOracle } from './execution-oracle.js';
import { buildB4Boundary } from '../../../../tests/privacy/i07-gate2-b4-test-support.js';

describe('I07 Gate 2 B4 atomic repository mechanics', () => {
  it('is idempotent only for the exact same occurrence boundary', () => {
    const boundary = buildB4Boundary();
    const oracle = createPrivacyExplorerExecutionOracle();
    expect(oracle.create(boundary)).toBe(oracle.create(boundary));
    expect(oracle.inspect(oracle.create(boundary))).toMatchObject({
      occurrenceId: boundary.request.occurrence.requestId,
      state: executionRegistry.states[0],
      revision: 0,
      rawState: 'NEVER_CREATED',
      delivery: 'PENDING',
    });
  });

  it('keeps snapshots immutable and rejects fabricated handles', () => {
    const oracle = createPrivacyExplorerExecutionOracle();
    const handle = oracle.create(buildB4Boundary());
    const snapshot = oracle.inspect(handle);
    expect(() => {
      (snapshot as { state: string }).state = 'RELEASED';
    }).toThrow();
    expect(() => oracle.inspect(Object.freeze({}))).toThrow('unknown execution handle');
  });
});
