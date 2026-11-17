import { afterEach, expect, it, vi } from 'vitest';
import { newReviewCustody } from './local-recovery-model';

afterEach(() => vi.unstubAllEnvs());

it('keeps recovery custody unchanged with execution-only request budgets', () => {
  vi.stubEnv('OPENPC_LOCAL_RUNTIME', '1');
  vi.stubEnv('OPENPC_LOCAL_RUNTIME_QA_FIXTURE', '1');
  vi.stubEnv('OPENPC_LOCAL_QA_DURATION_PROFILE', undefined);
  vi.stubEnv('OPENPC_LOCAL_QA_EXECUTION_PROFILE', 'LOCAL_QA_10X');
  expect(newReviewCustody(1_000)).toEqual({ issuedAt: 1_000 });
});
