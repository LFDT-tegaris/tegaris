import { expect, it } from 'vitest';
import {
  localQaDurationMultiplier,
  localQaExecutionTimeoutMs,
} from './local-qa-duration-profile.js';
const qa = {
  OPENPC_LOCAL_RUNTIME: '1',
  OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
  OPENPC_LOCAL_QA_DURATION_PROFILE: 'LOCAL_QA_10X',
};
it('retains every normal execution budget without the explicit profile', () => {
  expect(localQaDurationMultiplier({})).toBe(1);
  expect(localQaExecutionTimeoutMs(45_000, {})).toBe(45_000);
  expect(
    localQaExecutionTimeoutMs(45_000, {
      OPENPC_LOCAL_RUNTIME: '1',
      OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    }),
  ).toBe(45_000);
});
it('admits exactly tenfold finite budgets with all local opt-ins', () => {
  expect(localQaDurationMultiplier(qa)).toBe(10);
  expect(localQaExecutionTimeoutMs(45_000, qa)).toBe(450_000);
});
it.each([
  { ...qa, OPENPC_LOCAL_RUNTIME: undefined },
  { ...qa, OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '0' },
  { ...qa, OPENPC_LOCAL_QA_DURATION_PROFILE: '10X' },
])('rejects incomplete or unknown local profile %j', (environment) => {
  expect(() => localQaExecutionTimeoutMs(45_000, environment)).toThrow();
});
it.each([0, -1, 1.5, NaN, Infinity, 3_600_001])('rejects unbounded execution input %s', (value) => {
  expect(() => localQaExecutionTimeoutMs(value, qa)).toThrow();
});

const executionOnly = {
  OPENPC_LOCAL_RUNTIME: '1',
  OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
  OPENPC_LOCAL_QA_EXECUTION_PROFILE: 'LOCAL_QA_10X',
};
it('extends execution without changing the authority duration multiplier', () => {
  expect(localQaExecutionTimeoutMs(120_000, executionOnly)).toBe(1_200_000);
  expect(localQaDurationMultiplier(executionOnly)).toBe(1);
  expect(localQaExecutionTimeoutMs(45_000, { ...qa, ...executionOnly })).toBe(450_000);
});
it.each([
  { ...executionOnly, OPENPC_LOCAL_RUNTIME: undefined },
  { ...executionOnly, OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '0' },
  { ...executionOnly, OPENPC_LOCAL_QA_EXECUTION_PROFILE: '10X' },
  { ...executionOnly, OPENPC_LOCAL_QA_DURATION_PROFILE: 'INVALID' },
])('rejects incomplete or unknown execution opt-ins %j', (environment) => {
  expect(() => localQaExecutionTimeoutMs(45_000, environment)).toThrow();
});
